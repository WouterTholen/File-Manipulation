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
from collections import Counter
from pathlib import Path


HASH_BLOCK_SIZE = 1024 * 1024  # Read files in 1 MiB pieces.


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Report duplicate files. This program never deletes files."
    )
    parser.add_argument("root", type=Path, help="Folder containing the folders to compare")
    parser.add_argument(
        "--all-folders",
        action="store_true",
        help="Also compare every nested folder (can produce many results)",
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
            "--keep_file",
            type=Path,
            help="Keep files with this in their path and remove duplicates of this file",
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

# Create a manifest of a file
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
        print("Only returning the current folder")
        return sorted(path for path in root.iterdir() if path.is_dir() and not path.is_symlink())

    candidates = []
    for current, directories, _ in os.walk(root, followlinks=False):
        current_path = Path(current)
        # Replace the directories list in place so the for loop now uses the new list without symlinks
        directories[:] = [name for name in directories if not (current_path / name).is_symlink()]
        if current_path != root:
            candidates.append(current_path)
    return sorted(candidates)

def is_inside_path(full_path: Path, keep_path: Path) -> bool:
    return str(keep_path).replace("\\", "/") in str(full_path).replace("\\", "/")

def keep_specific_file(sorted_match, keep_path):
    if sorted_match:
#        print("\nSorted Match found\n")
        print(f"The path to keep is {keep_path}")
        for number, group in enumerate(sorted_match, start=1):
            print(group)
#            print(f"Group {number} ({len(sorted_match[group])} identical files):\n")
            print(f" Size: {group[0]}\n")
            keeper = ""
            for path in sorted_match[group]:
#                print(f"  {path}\n")
                if is_inside_path(path,keep_path):
                    keeper = path
                    print(f"\n!!! Path found in file {path}\n")
#                else:
#                    print(f"Path not found in file {path}")
            if not keeper == "":
                for path in sorted_match[group]:
                    if not path == keeper:
                        print(f"Deleting {path}")
#                        try:
#                            os.remove(path)
#                        except:
#                            print("Trouble deleting" + str(path)))
                    else:
                        print(f"!!!Keeping {path}")
    ## TODO add:
    ## for path in sorted_match[group]
    ##   if path.contains "\Prive\Muziek\"
    ##     rm all entries in the group except \Prive\Muziek\
    else:
       print("\nNo matching files found\n")

def main() -> int:
    args = parse_arguments()
    root = args.root.resolve()
    if not root.is_dir():
        print(f"Not a directory: {root}", file=sys.stderr)
        return 2

    cache = load_cache(args.cache)
    statistics = defaultdict(int)
    problems: list[str] = []
#    folders: list[tuple[Path, dict]] = []
    start = time.monotonic()

#  Actually compare files to eachother
#    print(f"\n\nThe list of candidates is: {candidates}\n\n")
    all_files = defaultdict(list)
    candidates = candidate_folders(root, args.all_folders)
    total_folders = len(candidates)
    print(f"Scanning {total_folders} candidate folders...")
    for number, folder in enumerate(candidates, start=1):
        print(f"[{number}/{total_folders}] {folder}")
        folder_files = [file for file in os.listdir(folder) if os.path.isfile(os.path.join(folder,file))]
        if(folder_files):
#            print(f"\n\nThe files in this folder are: {folder_files}")
            for file in folder_files:
                file_path = Path(os.path.join(folder,file))
                try:
                    stat = file_path.stat()
                    all_files[(stat.st_size, hash_file(file_path, cache, statistics))].append(file_path)
#                    print("file added\n")
                except OSError as error:
                    problems.append(f"Could not hash {file_path}: {error}")
                    return None
#    print(f"\n\nAll files: {all_files}")


    exact_match = defaultdict(list)
    if all_files:
#        print(f"\n\nThe dictionary with all files files is {all_files}")
        for entry in all_files:
#            print(f"The file {entry} has length {len(all_files[entry])}")
            if len(all_files[entry]) > 1:
                exact_match[entry] = all_files[entry]
    sorted_match = dict(sorted(exact_match.items(), key=lambda x: len(x[1]), reverse = True))
#    print(f"\n\nThe list of exact matches{sorted_match}")

    if(args.keep_file):
        print("\nKeepfile is active\n")
        keep_specific_file(sorted_match, args.keep_file)

    elapsed = time.monotonic() - start
    args.report.parent.mkdir(parents=True, exist_ok=True)
    with args.report.open("w", encoding="utf-8") as report:
        print("\n\nWriting the report.")
        report.write("FOLDER COMPARISON REPORT\n")
        report.write("This report is read-only; the script did not delete or modify scanned files.\n\n")
        report.write(f"Root: {root}\n")
        report.write(f"Candidate mode: {'all nested folders' if args.all_folders else 'direct child files'}\n")
        report.write(f"Files scanned successfully: {len(all_files)}\n")
        report.write(f"Exact duplicate groups: {len(sorted_match)}\n\n")

        report.write("EXACT DUPLICATE FOLDERS\n")
        report.write("=" * 25 + "\n")
        if sorted_match:
            print("Exact matches found")
            for number, group in enumerate(sorted_match, start=1):
#                print(group)
                report.write(f"\nGroup {number} ({len(sorted_match[group])} identical files):\n")
                report.write(f"  Size: {group[0]}\n")
                for path in sorted_match[group]:
                    report.write(f"  {path}\n")
        else:
            report.write("None found.\n")

        report.write("\nSCAN NOTES\n")
        report.write("=" * 10 + "\n")
        report.write(f"Files hashed this run: {statistics['hashed_files']}\n")
        report.write(f"Hashes reused from cache: {statistics['cache_hits']}\n")
        report.write(f"Bytes read for hashing: {statistics['hashed_bytes']}\n")
#        report.write(f"Near-match comparisons performed: {min(comparisons, args.max_near_comparisons)}\n")
        report.write(f"Elapsed time: {elapsed:.1f} seconds\n")
        if problems:
            report.write("\nFolders with unreadable files or symbolic links were excluded:\n")
            for problem in problems:
                report.write(f"  {problem}\n")
    print("\n\nDone writing file")
    save_cache(args.cache, cache)
    print(f"\nReport written to: {args.report.resolve()}")
    print(f"Hash cache written to: {args.cache.resolve()}")
#    print(f"Exact duplicate groups: {len(exact_groups)}")
#    print(f"Near matches: {len(near_matches)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
