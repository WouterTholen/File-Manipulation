"""Find identical (and nearly identical) folders without changing any files.

By default, the folders compared are the direct child folders of ROOT.  This
matches the usual "several backup folders in one place" layout and keeps the
near-match search manageable.  Use --all-folders only when you intentionally
want every nested folder to become a candidate.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time
from collections import defaultdict
from pathlib import Path


HASH_BLOCK_SIZE = 1024 * 1024  # Read files in 1 MiB pieces.


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Report duplicate folders. This program never deletes files."
    )
    parser.add_argument("root", type=Path, help="Folder containing the folders to compare")
    parser.add_argument(
        "--all-folders",
        action="store_true",
        help="Also compare every nested folder (can produce many results)",
    )
    parser.add_argument(
        "--near",
        type=int,
        default=2,
        help="Also report folders differing by at most this many file entries (default: 2)",
    )
    parser.add_argument(
        "--include-empty",
        action="store_true",
        help="Include empty folders as duplicate and near-match candidates",
    )
    parser.add_argument(
        "--report",
        type=Path,
        default=Path("folder-comparison-report.txt"),
        help="Where to write the text report (default: folder-comparison-report.txt)",
    )
    parser.add_argument(
        "--cache",
        type=Path,
        default=Path("folder-hash-cache.json"),
        help="Reusable file-hash cache (default: folder-hash-cache.json)",
    )
    parser.add_argument(
        "--max-near-comparisons",
        type=int,
        default=2_000_000,
        help="Safety limit for near-match comparisons (default: 2000000)",
    )
    return parser.parse_args()


def load_cache(cache_path: Path) -> dict:
    """Load old hashes. A corrupt or missing cache is safe to ignore."""
    try:
        with cache_path.open("r", encoding="utf-8") as handle:
            cache = json.load(handle)
        return cache if isinstance(cache, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def save_cache(cache_path: Path, cache: dict) -> None:
    """Save hashes only after the scan has finished."""
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = cache_path.with_suffix(cache_path.suffix + ".tmp")
    with temporary_path.open("w", encoding="utf-8") as handle:
        json.dump(cache, handle, separators=(",", ":"))
    temporary_path.replace(cache_path)


def hash_file(file_path: Path, cache: dict, statistics: dict) -> str:
    """Return a SHA-256 hash, reusing a hash when size and timestamp agree."""
    stat = file_path.stat()
    cache_key = str(file_path.resolve())
    cached = cache.get(cache_key)

    if (
        isinstance(cached, dict)
        and cached.get("size") == stat.st_size
        and cached.get("mtime_ns") == stat.st_mtime_ns
        and isinstance(cached.get("sha256"), str)
    ):
        statistics["cache_hits"] += 1
        return cached["sha256"]

    hasher = hashlib.sha256()
    with file_path.open("rb") as handle:
        while block := handle.read(HASH_BLOCK_SIZE):
            hasher.update(block)

    digest = hasher.hexdigest()
    cache[cache_key] = {
        "size": stat.st_size,
        "mtime_ns": stat.st_mtime_ns,
        "sha256": digest,
    }
    statistics["hashed_files"] += 1
    statistics["hashed_bytes"] += stat.st_size
    return digest


def make_manifest(folder: Path, cache: dict, statistics: dict, problems: list[str]) -> dict | None:
    """Map each relative file path to (size, SHA-256). Return None if incomplete."""
    manifest = {}
    walk_failed = False

    def walk_error(error: OSError) -> None:
        nonlocal walk_failed
        walk_failed = True
        problems.append(f"Could not read {error.filename}: {error.strerror}")

    for current, directories, filenames in os.walk(folder, onerror=walk_error, followlinks=False):
        current_path = Path(current)
        # Directory links are deliberately not followed: following one may loop.
        symlink_directories = [name for name in directories if (current_path / name).is_symlink()]
        if symlink_directories:
            problems.append(f"Skipped folder containing symbolic link: {folder}")
            return None

        for name in filenames:
            file_path = current_path / name
            if file_path.is_symlink():
                problems.append(f"Skipped symbolic link: {file_path}")
                return None
            try:
                relative_name = file_path.relative_to(folder).as_posix()
                stat = file_path.stat()
                manifest[relative_name] = (stat.st_size, hash_file(file_path, cache, statistics))
            except OSError as error:
                problems.append(f"Could not hash {file_path}: {error}")
                return None

    return None if walk_failed else manifest


def manifest_fingerprint(manifest: dict) -> str:
    """Create one stable fingerprint for a complete folder manifest."""
    hasher = hashlib.sha256()
    for relative_name, (size, digest) in sorted(manifest.items()):
        hasher.update(relative_name.encode("utf-8", "surrogateescape"))
        hasher.update(b"\0")
        hasher.update(str(size).encode("ascii"))
        hasher.update(b"\0")
        hasher.update(digest.encode("ascii"))
        hasher.update(b"\n")
    return hasher.hexdigest()


def folder_differences(first: dict, second: dict) -> list[str]:
    """Return paths whose name, size, or contents differ between two folders."""
    return [
        name
        for name in sorted(set(first) | set(second))
        if first.get(name) != second.get(name)
    ]


def candidate_folders(root: Path, all_folders: bool) -> list[Path]:
    if not all_folders:
        return sorted(path for path in root.iterdir() if path.is_dir() and not path.is_symlink())

    candidates = []
    for current, directories, _ in os.walk(root, followlinks=False):
        current_path = Path(current)
        directories[:] = [name for name in directories if not (current_path / name).is_symlink()]
        if current_path != root:
            candidates.append(current_path)
    return sorted(candidates)


def main() -> int:
    args = parse_arguments()
    root = args.root.resolve()
    if not root.is_dir():
        print(f"Not a directory: {root}", file=sys.stderr)
        return 2
    if args.near < 0 or args.max_near_comparisons < 0:
        print("--near and --max-near-comparisons must be zero or positive.", file=sys.stderr)
        return 2

    cache = load_cache(args.cache)
    statistics = defaultdict(int)
    problems: list[str] = []
    folders: list[tuple[Path, dict]] = []
    start = time.monotonic()

    candidates = candidate_folders(root, args.all_folders)
    print(f"Scanning {len(candidates)} candidate folders...")
    for number, folder in enumerate(candidates, start=1):
        print(f"[{number}/{len(candidates)}] {folder}")
        manifest = make_manifest(folder, cache, statistics, problems)
        if manifest is None:
            continue
        # Empty folders can be very numerous, so they are opt-in.
        if manifest or args.include_empty:
            folders.append((folder, manifest))

    # Equal manifests produce the same compact fingerprint.
    fingerprint_groups: dict[str, list[tuple[Path, dict]]] = defaultdict(list)
    for folder, manifest in folders:
        fingerprint_groups[manifest_fingerprint(manifest)].append((folder, manifest))
    exact_groups = [group for group in fingerprint_groups.values() if len(group) > 1]
#    print(f"TEST {exact_groups}")
    near_matches: list[tuple[Path, Path, list[str]]] = []
    comparisons = 0
    near_limit_reached = False
    for first_index, (first_folder, first_manifest) in enumerate(folders):
        for second_folder, second_manifest in folders[first_index + 1 :]:
            # At least this many entries must differ if the file counts differ.
            if abs(len(first_manifest) - len(second_manifest)) > args.near:
                continue
            comparisons += 1
            if comparisons > args.max_near_comparisons:
                near_limit_reached = True
                break
            differences = folder_differences(first_manifest, second_manifest)
            if 0 < len(differences) <= args.near:
                near_matches.append((first_folder, second_folder, differences))
        if near_limit_reached:
            break

    elapsed = time.monotonic() - start
    args.report.parent.mkdir(parents=True, exist_ok=True)
    with args.report.open("w", encoding="utf-8") as report:
        report.write("FOLDER COMPARISON REPORT\n")
        report.write("This report is read-only; the script did not delete or modify scanned files.\n\n")
        report.write(f"Root: {root}\n")
        report.write(f"Candidate mode: {'all nested folders' if args.all_folders else 'direct child folders'}\n")
        report.write(f"Empty folders included: {args.include_empty}\n")
        report.write(f"Folders scanned successfully: {len(folders)}\n")
        report.write(f"Exact duplicate groups: {len(exact_groups)}\n\n")
        
        report.write("EXACT DUPLICATE FOLDERS\n")
        report.write("=" * 25 + "\n")
        if exact_groups:
            for number, group in enumerate(exact_groups, start=1):
                report.write(f"\nGroup {number} ({len(group)} identical folders):\n")
                for folder, _ in group:
                    report.write(f"  {folder}\n")
        else:
            report.write("None found.\n")

        report.write("\nNEAR MATCHES\n")
        report.write("=" * 12 + "\n")
        report.write(f"Folders differing in 1 to {args.near} file entries.\n")
        if near_matches:
            for first_folder, second_folder, differences in near_matches:
                report.write(f"\n{first_folder}\n{second_folder}\n")
                report.write(f"Different entries ({len(differences)}):\n")
                for name in differences:
                    report.write(f"  {name}\n")
        else:
            report.write("None found.\n")
        if near_limit_reached:
            report.write(
                f"\nWARNING: near-match search stopped after {args.max_near_comparisons} comparisons. "
                "Exact-duplicate results are complete; near-match results are not.\n"
            )

        report.write("\nSCAN NOTES\n")
        report.write("=" * 10 + "\n")
        report.write(f"Files hashed this run: {statistics['hashed_files']}\n")
        report.write(f"Hashes reused from cache: {statistics['cache_hits']}\n")
        report.write(f"Bytes read for hashing: {statistics['hashed_bytes']}\n")
        report.write(f"Near-match comparisons performed: {min(comparisons, args.max_near_comparisons)}\n")
        report.write(f"Elapsed time: {elapsed:.1f} seconds\n")
        if problems:
            report.write("\nFolders with unreadable files or symbolic links were excluded:\n")
            for problem in problems:
                report.write(f"  {problem}\n")

    save_cache(args.cache, cache)
    print(f"\nReport written to: {args.report.resolve()}")
    print(f"Hash cache written to: {args.cache.resolve()}")
    print(f"Exact duplicate groups: {len(exact_groups)}")
    print(f"Near matches: {len(near_matches)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
