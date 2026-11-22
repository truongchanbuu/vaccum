import argparse
import errno
import json
import os
import stat
import sys


MAX_DEPTH = 128
DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


def mount_id(fd):
    with open(f"/proc/self/fdinfo/{fd}", encoding="ascii") as stream:
        for line in stream:
            if line.startswith("mnt_id:"):
                return int(line.split(":", 1)[1])
    raise OSError(errno.EIO, "Mount identity unavailable")


def open_root(path):
    if not path:
        raise OSError(errno.ENOENT, "Empty root")
    if ".." in path.split("/"):
        raise OSError(errno.EINVAL, "Parent traversal is excluded")
    fd = os.open("/" if os.path.isabs(path) else ".", DIRECTORY_FLAGS)
    try:
        for part in path.split("/"):
            if part and part != ".":
                child = os.open(part, DIRECTORY_FLAGS, dir_fd=fd)
                os.close(fd)
                fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


def scan(roots):
    report = {
        "schema_version": 1,
        "status": "complete",
        "complete": True,
        "roots": [{"label": f"root-{number}", "input": os.fspath(path)} for number, path in enumerate(roots, 1)],
        "policy": {
            "scope": "Selected directory objects; paths are root-relative observations, not an atomic snapshot.",
            "skips": "Symlinks, special files, repeated directories and nested mount points are excluded.",
            "max_depth": MAX_DEPTH,
            "privacy": "Local metadata only; paths may be sensitive. Review before sharing.",
            "sizes": "Regular-file logical and allocated bytes from stat; totals count each device/inode once. Reclaimable space is unknown.",
            "read_only": "No requested filesystem mutations; filesystem access may update access times.",
        },
        "findings": [],
        "skipped": [],
        "totals": {
            "unique_regular_files": 0,
            "logical_bytes": 0,
            "allocated_bytes": 0,
            "estimated_reclaimable_bytes": None,
        },
    }
    directories = set()
    files = set()
    stack = []

    def skip(root, path, code, reason, error=False, number=None):
        item = {"root": root, "path": path, "code": code, "reason": reason}
        if number is not None:
            item["errno"] = number
        report["skipped"].append(item)
        if error:
            report["complete"] = False

    def finding(root, path, metadata):
        regular = stat.S_ISREG(metadata.st_mode)
        temporary = regular and (os.path.basename(path).lower().endswith((".tmp", ".temp", ".swp", "~")))
        report["findings"].append({
            "root": root,
            "path": path,
            "type": "regular" if regular else "directory",
            "category": "temporary-candidate" if temporary else "regular" if regular else "directory",
            "logical_bytes": metadata.st_size if regular else None,
            "allocated_bytes": metadata.st_blocks * 512 if regular else None,
            "estimated_reclaimable_bytes": None,
            "reason": "Name has a temporary-looking suffix." if temporary else "Observed regular file metadata." if regular else "Observed directory; contents scanned within policy.",
            "uncertainty": "Metadata does not establish whether an item is unused or safe to remove. Sizes are observations and may change; allocated space may be shared.",
            "suggested_action": "Review manually; no removal or move is authorized.",
        })
        identity = (metadata.st_dev, metadata.st_ino)
        if regular and identity not in files:
            files.add(identity)
            report["totals"]["unique_regular_files"] += 1
            report["totals"]["logical_bytes"] += metadata.st_size
            report["totals"]["allocated_bytes"] += metadata.st_blocks * 512

    def enter(fd, root, path, depth, expected, root_mount=None):
        try:
            actual = os.fstat(fd)
            if (actual.st_dev, actual.st_ino) != (expected.st_dev, expected.st_ino):
                skip(root, path, "changed", "Directory identity changed before enumeration.", True)
                return
            try:
                current_mount = mount_id(fd)
            except (OSError, ValueError) as error:
                skip(root, path, "mount_unavailable", "Cannot verify mount boundary; directory excluded.", True, getattr(error, "errno", None))
                return
            if root_mount is not None and current_mount != root_mount:
                skip(root, path, "mount_boundary", "Nested mount point excluded by traversal policy.")
                return
            identity = (actual.st_dev, actual.st_ino)
            if identity in directories:
                skip(root, path, "overlap", "Directory already scanned through another selected path.")
                return
            iterator = os.scandir(fd)
            directories.add(identity)
            finding(root, path, actual)
            stack.append((fd, iterator, root, path, depth, current_mount))
            fd = None
        except OSError as error:
            skip(root, path, "directory_unavailable", "Cannot enumerate directory metadata.", True, error.errno)
        finally:
            if fd is not None:
                os.close(fd)

    try:
        for number, path in enumerate(roots, 1):
            root = f"root-{number}"
            try:
                fd = open_root(os.fspath(path))
            except OSError as error:
                skip(root, ".", "root_unavailable", "Root must be an accessible directory without symlink or parent-traversal components.", True, error.errno)
                continue
            try:
                expected = os.fstat(fd)
            except OSError as error:
                os.close(fd)
                skip(root, ".", "root_unavailable", "Cannot read selected directory metadata.", True, error.errno)
                continue
            except BaseException:
                os.close(fd)
                raise
            enter(fd, root, ".", 0, expected)
            while stack:
                parent_fd, iterator, label, parent_path, depth, parent_mount = stack[-1]
                try:
                    entry = next(iterator)
                except StopIteration:
                    iterator.close()
                    os.close(parent_fd)
                    stack.pop()
                    continue
                except OSError as error:
                    skip(label, parent_path, "directory_unavailable", "Directory listing was interrupted by an operating-system error.", True, error.errno)
                    iterator.close()
                    os.close(parent_fd)
                    stack.pop()
                    continue
                relative = entry.name if parent_path == "." else parent_path + "/" + entry.name
                try:
                    metadata = os.stat(entry.name, dir_fd=parent_fd, follow_symlinks=False)
                    if stat.S_ISLNK(metadata.st_mode):
                        skip(label, relative, "symlink", "Symbolic link excluded; target was not followed.")
                    elif stat.S_ISREG(metadata.st_mode):
                        finding(label, relative, metadata)
                    elif stat.S_ISDIR(metadata.st_mode):
                        if depth >= MAX_DEPTH:
                            skip(label, relative, "depth_limit", "Directory depth exceeds the coverage limit.", True)
                        else:
                            child_fd = os.open(entry.name, DIRECTORY_FLAGS, dir_fd=parent_fd)
                            enter(child_fd, label, relative, depth + 1, metadata, parent_mount)
                    else:
                        skip(label, relative, "special_file", "Special file excluded; no contents were opened.")
                except OSError as error:
                    skip(label, relative, "entry_unavailable", "Entry disappeared, changed, or metadata access was denied.", True, error.errno)
    except KeyboardInterrupt:
        report["status"] = "interrupted"
        report["complete"] = False
    finally:
        for fd, iterator, *_ in reversed(stack):
            iterator.close()
            os.close(fd)
    if report["status"] != "interrupted" and not report["complete"]:
        report["status"] = "partial"
    return report


def human_report(report):
    lines = [f"Vaccum scan: {report['status']} (within stated traversal policy)"]
    for root in report["roots"]:
        lines.append(f"{root['label']}: {json.dumps(root['input'], ensure_ascii=True)}")
    for value in report["policy"].values():
        lines.append(str(value))
    for item in report["findings"]:
        location = json.dumps(item["root"] + ":" + item["path"], ensure_ascii=True)
        lines.append(f"{location} [{item['category']}] logical={item['logical_bytes']} allocated={item['allocated_bytes']} reclaimable=unknown")
        lines.append(f"  {item['reason']} {item['uncertainty']} {item['suggested_action']}")
    for item in report["skipped"]:
        location = json.dumps(item["root"] + ":" + item["path"], ensure_ascii=True)
        lines.append(f"Skipped {location} [{item['code']}]: {item['reason']}")
    totals = report["totals"]
    lines.append(f"Unique regular files: {totals['unique_regular_files']}; logical bytes: {totals['logical_bytes']}; allocated bytes: {totals['allocated_bytes']}; reclaimable: unknown")
    return "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Review local Linux files and installed packages.")
    commands = parser.add_subparsers(dest="command", required=True)
    for name, help_text in (("scan", "Read-only selected directory metadata scan."),
                            ("recommend", "Propose folder organization without moving files."),
                            ("ai-report", "Preview metadata to manually share with your chosen AI; no network calls.")):
        command = commands.add_parser(name, help=help_text)
        command.add_argument("roots", metavar="ROOT", nargs="+")
        if name == "ai-report":
            command.add_argument("--include-paths", action="store_true", help="Include local paths in the preview; review before sharing.")
        else:
            command.add_argument("--format", choices=("human", "json"), default="human")
    command = commands.add_parser("apps", help="Read native dpkg package inventory; packages are not desktop applications.")
    command.add_argument("--admindir", help="Explicit dpkg database directory; defaults to the system database.")
    command.add_argument("--format", choices=("human", "json"), default="human")
    for name, help_text in (("cleanup", "Preview selected targets for native trash; --apply requires interactive approval."),
                            ("uninstall", "Preview native package removal; --apply requires interactive approval.")):
        command = commands.add_parser(name, help=help_text)
        if name == "cleanup":
            command.add_argument("roots", metavar="ROOT", nargs="+")
            command.add_argument("--target", action="append", required=True, metavar="PATH",
                                 help="Exact target path relative to the working directory, or absolute; repeat to select more.")
        else:
            command.add_argument("packages", metavar="PACKAGE", nargs="+")
            command.add_argument("--root", help="Explicit native dpkg installation root; defaults to the system root.")
        command.add_argument("--apply", action="store_true", help="Request execution after reviewing the plan and typing its exact confirmation phrase.")
        command.add_argument("--format", choices=("human", "json"), default="human")
    args = parser.parse_args(argv)
    if args.command in {"cleanup", "uninstall"}:
        from vaccum_actions import cleanup, uninstall

        def confirm(plan):
            print(json.dumps(plan, ensure_ascii=True, indent=2), file=sys.stderr)
            if not args.apply:
                return None
            if not sys.stdin.isatty():
                print("Applying actions requires an interactive terminal and the exact confirmation phrase.", file=sys.stderr)
                return None
            print("Type the confirmation_phrase value exactly (without JSON quotes): ", end="", file=sys.stderr, flush=True)
            try:
                return sys.stdin.readline().rstrip("\r\n")
            except EOFError:
                return None

        try:
            report = cleanup(args.roots, args.target, confirm) if args.command == "cleanup" else uninstall(args.packages, confirm, root=args.root)
        except KeyboardInterrupt:
            report = {"schema_version": 1, "action": args.command, "status": "interrupted", "complete": False,
                      "warnings": ["Action interrupted; inspect current targets and native state before retrying."]}
        if not args.apply and report["status"] == "cancelled" and report.get("plan") is not None:
            for item in report.get("items", []):
                if item["status"] == "cancelled":
                    item["status"] = "planned"
            report["complete"] = all(item["status"] == "planned" for item in report.get("items", []))
            report["status"] = "preview" if report["complete"] else "partial"
        output = json.dumps(report, ensure_ascii=True, indent=2)
        if args.format == "human":
            output = f"Vaccum {args.command}: {report['status']}\n" + output
    elif args.command == "apps":
        from vaccum_inventory import inventory
        report = inventory(args.admindir)
        if args.format == "json":
            output = json.dumps(report, ensure_ascii=True, indent=2)
        else:
            lines = [f"Vaccum package inventory: {report['status']}", report.get("scope", ""),
                     "Database: " + json.dumps(report.get("database"), ensure_ascii=True)]
            for item in report["installed_packages"]:
                lines.append(json.dumps(item["package_id"] + " " + item["version"], ensure_ascii=True)
                             + f" estimated installed bytes={item['estimated_installed_bytes']}; reclaimable=unknown")
                lines.append("  " + item["reason"] + " " + item["uncertainty"] + " " + item["suggested_action"])
            for error in report["errors"]:
                lines.append(json.dumps(error, ensure_ascii=True))
            output = "\n".join(lines)
    else:
        report = scan(args.roots)
        if args.command == "ai-report":
            from vaccum_analysis import build_ai_handoff
            output = build_ai_handoff(report, include_paths=args.include_paths)
        elif args.command == "recommend":
            from vaccum_analysis import propose_structure
            proposal = propose_structure(report)
            proposal["roots"] = report["roots"]
            proposal["skipped"] = report["skipped"]
            output = json.dumps(proposal, ensure_ascii=True, indent=2)
            if args.format == "human":
                output = "Folder organization proposals; review references before any move.\n" + output
        else:
            output = json.dumps(report, ensure_ascii=True, indent=2) if args.format == "json" else human_report(report)
    print(output)
    if not report["complete"]:
        print("Result incomplete; review reported errors, skipped entries and coverage limits.", file=sys.stderr)
    return 130 if report["status"] == "interrupted" else 0 if report["complete"] else 1


if __name__ == "__main__":
    sys.exit(main())
