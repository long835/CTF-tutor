"""
ingest.py

Embeds every ArchiveEntry JSON file under data/archive/ into the local
ChromaDB vector store, via retriever.py's Retriever.index_directory().

Safe to re-run any time you add or edit archive entries: indexing uses a
deterministic id per entry (category + slugified challenge name), so
re-running upserts in place instead of duplicating.

Usage:
    python ingest.py                       # index data/archive/
    python ingest.py path/to/other_archive  # index a different directory
    python ingest.py --reset                # wipe the store first, then index
"""

import argparse
import sys
from typing import Optional

from retriever import Retriever


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "archive_dir", nargs="?", default="data/archive",
        help="directory of ArchiveEntry JSON files to index (default: data/archive)",
    )
    parser.add_argument(
        "--reset", action="store_true",
        help="wipe the vector store before indexing (use after deleting/renaming archive entries)",
    )
    parser.add_argument(
        "--persist-dir", default=None,
        help="chromadb persistence directory (default: data/chroma)",
    )
    return parser


def main(argv=None, retriever: Optional[Retriever] = None) -> int:
    """
    Runs the ingest. `retriever` can be injected (e.g. with a fake
    collection) for testing without a real chromadb/Ollama setup; normally
    left as None so a real Retriever() gets built from the parsed args.
    """
    args = _build_arg_parser().parse_args(argv)

    if retriever is None:
        try:
            retriever = Retriever(persist_dir=args.persist_dir)
        except RuntimeError as e:
            print(f"error: {e}", file=sys.stderr)
            return 1

    if args.reset:
        print("resetting vector store...")
        retriever.reset()

    count = retriever.index_directory(args.archive_dir)
    plural = "y" if count == 1 else "ies"
    print(f"indexed {count} archive entr{plural} from {args.archive_dir}")
    print(f"vector store now holds {retriever.count()} entries total")
    return 0


if __name__ == "__main__":
    sys.exit(main())
