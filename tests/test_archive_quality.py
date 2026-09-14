import os
from schema import ArchiveEntry
from archive_quality import validate_entry, entry_fingerprint, load_existing_fingerprints


def make_entry(**kw):
    data = dict(challenge_name='Test Pattern', category='web', techniques=['jwt'], difficulty='easy', description='desc', explanation='why', solve_steps=['inspect'], references=['https://example.test/source'])
    data.update(kw)
    return ArchiveEntry(**data)


def test_valid_entry_has_no_errors():
    assert validate_entry(make_entry()) == []


def test_invalid_entry_is_rejected():
    errors = validate_entry(make_entry(challenge_name='Unknown', references=[]))
    assert any('challenge_name' in e for e in errors)
    assert any('reference' in e for e in errors)


def test_fingerprint_is_stable_and_reference_sensitive():
    a = make_entry()
    b = make_entry()
    c = make_entry(references=['https://example.test/other'])
    assert entry_fingerprint(a) == entry_fingerprint(b)
    assert entry_fingerprint(a) != entry_fingerprint(c)


def test_curated_archive_is_broader_than_original_and_valid():
    archive = 'data/archive'
    paths = [os.path.join(archive, n) for n in os.listdir(archive) if n.endswith('.json')]
    assert len(paths) >= 30
    categories = set()
    for path in paths:
        entry = ArchiveEntry.load(path)
        assert validate_entry(entry) == [], path
        categories.add(entry.category)
    assert {'pwn','rev','web','crypto','forensics','osint','misc','blockchain','mobile'} <= categories
