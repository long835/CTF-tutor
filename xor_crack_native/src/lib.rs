//! Repeating-key XOR cracker.
//!
//! Classic CryptoPals-style attack:
//!   1. Guess the key length by finding the size that minimizes the
//!      normalized Hamming distance between consecutive blocks of
//!      ciphertext (repeated XOR with a short key produces low edit
//!      distance between blocks of the correct length).
//!   2. Transpose the ciphertext into `keysize` columns (byte i of every
//!      block lands in column i mod keysize).
//!   3. Each column was produced by XOR-ing plaintext with a single,
//!      fixed key byte -- so crack each column independently as a
//!      single-byte XOR cipher, scoring candidate plaintexts against
//!      English letter-frequency statistics.
//!   4. Recombine the best byte per column into a full key candidate.
//!
//! This is the one part of CTF-tutor's toolkit that is genuinely
//! CPU-bound (trying up to `max_keysize` candidate lengths, each
//! requiring a 256-way single-byte search per column), which is why it
//! is worth a native extension rather than pure Python.

use pyo3::prelude::*;
use pyo3::types::PyBytes;

/// Reference English letter frequencies (including space), used to score
/// how "English-like" a candidate plaintext byte stream is. Values are
/// approximate percentages; unlisted bytes score 0.
fn english_freq(byte: u8) -> f64 {
    match byte.to_ascii_lowercase() {
        b' ' => 13.0,
        b'e' => 12.7,
        b't' => 9.1,
        b'a' => 8.2,
        b'o' => 7.5,
        b'i' => 7.0,
        b'n' => 6.7,
        b's' => 6.3,
        b'h' => 6.1,
        b'r' => 6.0,
        b'd' => 4.3,
        b'l' => 4.0,
        b'c' => 2.8,
        b'u' => 2.8,
        b'm' => 2.4,
        b'w' => 2.4,
        b'f' => 2.2,
        b'g' => 2.0,
        b'y' => 2.0,
        b'p' => 1.9,
        b'b' => 1.5,
        b'v' => 1.0,
        b'k' => 0.8,
        b'j' => 0.15,
        b'x' => 0.15,
        b'q' => 0.10,
        b'z' => 0.07,
        _ => 0.0,
    }
}

/// Score a byte slice: sum of English-frequency weight for letters/space,
/// with a heavy penalty per non-printable byte so garbage decodes score
/// far below real text.
fn english_score(data: &[u8]) -> f64 {
    let mut score = 0.0;
    for &b in data {
        if b.is_ascii_graphic() || b == b' ' {
            score += english_freq(b);
        } else if b == b'\n' || b == b'\t' {
            score += 0.5;
        } else {
            score -= 10.0; // control/high bytes are very unlikely in English plaintext
        }
    }
    score
}

fn hamming_distance(a: &[u8], b: &[u8]) -> u32 {
    a.iter()
        .zip(b.iter())
        .map(|(x, y)| (x ^ y).count_ones())
        .sum()
}

/// Rank candidate key sizes by normalized average Hamming distance
/// between consecutive blocks (lower is more likely correct). Averages
/// over up to `sample_blocks` block pairs to stay robust on short input.
fn guess_keysizes(data: &[u8], max_keysize: usize, top_n: usize) -> Vec<usize> {
    let sample_blocks = 8usize;
    let mut scored: Vec<(usize, f64)> = Vec::new();

    for keysize in 2..=max_keysize.min(data.len() / 2).max(2) {
        let blocks: Vec<&[u8]> = data.chunks(keysize).take(sample_blocks + 1).collect();
        if blocks.len() < 2 {
            continue;
        }
        let mut total = 0.0;
        let mut pairs = 0u32;
        for w in blocks.windows(2) {
            if w[0].len() == keysize && w[1].len() == keysize {
                total += hamming_distance(w[0], w[1]) as f64 / keysize as f64;
                pairs += 1;
            }
        }
        if pairs > 0 {
            scored.push((keysize, total / pairs as f64));
        }
    }

    // Sort by distance, but treat near-tied distances (within 10%) as equal
    // and prefer the smaller key size in that case -- a correct key size k
    // always produces a near-identical normalized distance at every
    // multiple of k (2k, 3k, ...), so without this the smallest (true)
    // key size can lose a close race to one of its own multiples.
    scored.sort_by(|a, b| {
        if (a.1 - b.1).abs() < a.1.max(b.1).max(0.01) * 0.10 {
            a.0.cmp(&b.0)
        } else {
            a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal)
        }
    });
    scored.into_iter().take(top_n).map(|(k, _)| k).collect()
}

/// Crack a single column (bytes all XOR-ed with the same key byte):
/// try all 256 candidate key bytes, return the one whose decoded column
/// scores highest as English text.
fn crack_column(column: &[u8]) -> (u8, f64) {
    let mut best_byte = 0u8;
    let mut best_score = f64::MIN;
    for key_byte in 0u16..=255 {
        let key_byte = key_byte as u8;
        let decoded: Vec<u8> = column.iter().map(|b| b ^ key_byte).collect();
        let score = english_score(&decoded);
        if score > best_score {
            best_score = score;
            best_byte = key_byte;
        }
    }
    (best_byte, best_score)
}

/// Attempt to crack `data` as repeating-key XOR ciphertext.
///
/// Returns up to `candidates` (key, plaintext, score) tuples, sorted by
/// descending score (best guess first). `max_keysize` bounds how long a
/// key is considered (CryptoPals-style attacks commonly use 2-40).
fn break_repeating_xor(
    data: &[u8],
    max_keysize: usize,
    candidates: usize,
) -> Vec<(Vec<u8>, Vec<u8>, f64)> {
    if data.is_empty() {
        return Vec::new();
    }
    // Score every candidate key size in range, not just the top few ranked
    // by Hamming distance: the Hamming-distance heuristic only orders
    // candidates, it does not reliably rank the true key size #1 (longer
    // keys and coincidental low-distance false positives can outrank it).
    // Scoring is the expensive step, but it's cheap enough in Rust that
    // exhaustively scoring every key size up to max_keysize is still far
    // faster than the pure-Python narrow-search version, and it removes
    // an entire class of "correct key size never even attempted" misses.
    let keysize_candidates = guess_keysizes(data, max_keysize, max_keysize);
    let mut results: Vec<(Vec<u8>, Vec<u8>, f64)> = Vec::new();

    for keysize in keysize_candidates {
        let mut key = vec![0u8; keysize];
        for col_idx in 0..keysize {
            let column: Vec<u8> = data.iter().skip(col_idx).step_by(keysize).copied().collect();
            let (key_byte, _) = crack_column(&column);
            key[col_idx] = key_byte;
        }
        let plaintext: Vec<u8> = data
            .iter()
            .enumerate()
            .map(|(i, b)| b ^ key[i % keysize])
            .collect();
        let score = english_score(&plaintext) / data.len().max(1) as f64;
        results.push((key, plaintext, score));
    }

    // A key size that is an exact multiple of the true key length decodes
    // to the identical plaintext (and therefore ties on score). Collapse
    // those duplicates down to the shortest key that produces each
    // distinct plaintext, so the tutor doesn't present "KEY" and "KEYKEY"
    // as two separate answers.
    let mut by_plaintext: Vec<(Vec<u8>, Vec<u8>, f64)> = Vec::new();
    for (key, plaintext, score) in results.into_iter() {
        if let Some(existing) = by_plaintext.iter_mut().find(|(_, p, _)| *p == plaintext) {
            if key.len() < existing.0.len() {
                existing.0 = key;
            }
        } else {
            by_plaintext.push((key, plaintext, score));
        }
    }

    by_plaintext.sort_by(|a, b| b.2.partial_cmp(&a.2).unwrap_or(std::cmp::Ordering::Equal));
    by_plaintext.truncate(candidates.max(1));
    by_plaintext
}

/// Python-visible entry point.
///
/// crack_repeating_xor(data: bytes, max_keysize: int = 40, candidates: int = 3)
///   -> List[Tuple[bytes, bytes, float]]
///
/// Each result is (key, plaintext, score); higher score = more
/// English-like. This does not guarantee a correct crack on ciphertext
/// that isn't repeating-key XOR or isn't English -- it's a ranked-guess
/// tool for the tutor to present, same as the rest of decode_toolkit.
#[pyfunction]
#[pyo3(signature = (data, max_keysize=40, candidates=3))]
fn crack_repeating_xor(
    py: Python<'_>,
    data: &[u8],
    max_keysize: usize,
    candidates: usize,
) -> PyResult<Vec<(Py<PyBytes>, Py<PyBytes>, f64)>> {
    let results = break_repeating_xor(data, max_keysize, candidates);
    Ok(results
        .into_iter()
        .map(|(key, plaintext, score)| {
            (
                PyBytes::new(py, &key).into(),
                PyBytes::new(py, &plaintext).into(),
                score,
            )
        })
        .collect())
}

#[pymodule]
fn xor_crack_native(_py: Python<'_>, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(crack_repeating_xor, m)?)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovers_short_english_key() {
        // Realistic-length sample: Hamming-distance keysize detection needs
        // enough blocks to be statistically reliable. On very short input
        // (a few dozen bytes) a multiple of the true key length can win by
        // noise alone -- that's an inherent property of the attack, not a
        // bug, so the unit test reflects a length CTF ciphertext blobs
        // actually tend to be.
        let plaintext: Vec<u8> = "THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG. \
            PACK MY BOX WITH FIVE DOZEN LIQUOR JUGS. HOW VEXINGLY QUICK DAFT \
            ZEBRAS JUMP. THE FIVE BOXING WIZARDS JUMP QUICKLY. SPHINX OF \
            BLACK QUARTZ, JUDGE MY VOW. WALTZ, NYMPH, FOR QUICK JIGS VEX \
            BUD. TWO DRIVEN JOCKS HELP FAX MY BIG QUIZ."
            .bytes()
            .collect();
        let key = b"KEY";
        let ciphertext: Vec<u8> = plaintext
            .iter()
            .enumerate()
            .map(|(i, b)| b ^ key[i % key.len()])
            .collect();

        let results = break_repeating_xor(&ciphertext, 10, 3);
        assert!(!results.is_empty());
        let (best_key, best_plain, _) = &results[0];
        assert_eq!(best_key.as_slice(), key);
        assert_eq!(best_plain.as_slice(), plaintext.as_slice());
    }

    #[test]
    fn empty_input_returns_no_candidates() {
        assert!(break_repeating_xor(&[], 40, 3).is_empty());
    }
}
