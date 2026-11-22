import os
import re
import secrets
import stat
import subprocess

from vaccum import DIRECTORY_FLAGS, MAX_DEPTH, mount_id


PACKAGE_ID = re.compile(r"[a-z0-9][a-z0-9+.-]+(?::[a-z0-9][a-z0-9-]*)?\Z")
SYSTEM_PATHS = ("/bin", "/boot", "/dev", "/etc", "/lib", "/lib64", "/proc", "/root", "/run", "/sbin", "/sys", "/usr", "/var")
ENVIRONMENT = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}


def _path(value):
    value = os.fspath(value)
    if not isinstance(value, str) or not value or "\0" in value or ".." in value.split("/"):
        raise ValueError("Use a literal path without parent traversal.")
    return "/" + os.path.abspath(value).lstrip("/")


def _identity(metadata, mounted):
    return (metadata.st_dev, metadata.st_ino, metadata.st_mode, metadata.st_uid, metadata.st_gid, mounted)


def _ancestry(path, user_root=None, expected=None, retain=False):
    uid = os.geteuid()
    fd = os.open("/", DIRECTORY_FLAGS)
    records = []
    current = "/"
    try:
        for component in [None] + [part for part in path.split("/") if part]:
            if component:
                child = os.open(component, DIRECTORY_FLAGS, dir_fd=fd)
                os.close(fd)
                fd = child
                current = os.path.join(current, component)
            metadata = os.fstat(fd)
            inside = user_root is not None and (current == user_root or current.startswith(user_root + "/"))
            sticky_ancestor = not inside and metadata.st_uid == 0 and metadata.st_mode & stat.S_ISVTX
            if metadata.st_uid not in (0, uid) or (metadata.st_mode & 0o022 and not sticky_ancestor):
                raise ValueError("Untrusted writable or foreign-owned path ancestry.")
            if inside and metadata.st_uid != uid:
                raise ValueError("Selected roots and parents must belong to the current user.")
            records.append((current, _identity(metadata, mount_id(fd))))
            if expected is not None and (len(records) > len(expected) or records[-1] != expected[len(records) - 1]):
                raise ValueError("Path ancestry identity or permissions changed.")
        if expected is not None and len(records) != len(expected):
            raise ValueError("Path ancestry changed.")
        if retain:
            retained = fd
            fd = None
            return records, retained
        return records
    finally:
        if fd is not None:
            os.close(fd)


def _trusted_backend(path):
    _ancestry(os.path.dirname(path))
    metadata = os.stat(path, follow_symlinks=False)
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_mode & 0o022 or not metadata.st_mode & 0o111:
        raise ValueError("Native backend is not a trusted system executable.")


def _run(command, timeout=120):
    _trusted_backend(command[0])
    environment = dict(ENVIRONMENT)
    if command[0] == "/usr/bin/gio":
        for key in ("HOME", "XDG_DATA_HOME", "XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS"):
            if key in os.environ:
                environment[key] = os.environ[key]
    return subprocess.run(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          text=True, encoding="utf-8", errors="replace", env=environment, timeout=timeout)


def _tree(path, expected_mount=None, owner=None, ancestry=None):
    records = []
    seen = set()
    paths = []
    logical = allocated = 0

    def visit(parent, name, relative, depth):
        nonlocal logical, allocated
        flags = os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC
        fd = os.open(name, flags, dir_fd=parent)
        try:
            metadata = os.fstat(fd)
            mounted = mount_id(fd)
            if expected_mount is not None and mounted != expected_mount:
                raise ValueError("Nested mount points are excluded.")
            if owner is not None and metadata.st_uid != owner:
                raise ValueError("Targets and their descendants must belong to the current user.")
            if not (stat.S_ISREG(metadata.st_mode) or stat.S_ISDIR(metadata.st_mode)):
                raise ValueError("Symlinks and special files are excluded.")
            if owner is not None and metadata.st_mode & 0o022:
                raise ValueError("Group or other writable targets are excluded.")
            records.append((relative, _identity(metadata, mounted), metadata.st_size, metadata.st_blocks,
                            metadata.st_mtime_ns, metadata.st_ctime_ns, metadata.st_nlink))
            paths.append(path if relative == "." else os.path.join(path, relative))
            identity = (metadata.st_dev, metadata.st_ino)
            if stat.S_ISREG(metadata.st_mode):
                if identity not in seen:
                    logical += metadata.st_size
                    allocated += metadata.st_blocks * 512
                    seen.add(identity)
                return
            if depth >= MAX_DEPTH:
                raise ValueError("Subtree exceeds the metadata depth limit.")
            directory = os.open(name, DIRECTORY_FLAGS, dir_fd=parent)
            try:
                if _identity(os.fstat(directory), mount_id(directory)) != _identity(metadata, mounted):
                    raise ValueError("Directory changed while validating.")
                with os.scandir(directory) as entries:
                    names = sorted(entry.name for entry in entries)
                for child in names:
                    visit(directory, child, child if relative == "." else relative + "/" + child, depth + 1)
                after = os.fstat(directory)
                if (after.st_mtime_ns, after.st_ctime_ns) != (metadata.st_mtime_ns, metadata.st_ctime_ns):
                    raise ValueError("Directory changed while validating.")
            finally:
                os.close(directory)
        finally:
            os.close(fd)

    _, parent = _ancestry(os.path.dirname(path), expected=ancestry, retain=True)
    try:
        visit(parent, os.path.basename(path), ".", 0)
    finally:
        os.close(parent)
    return tuple(records), paths, logical, allocated


def _package_owned(paths):
    for offset in range(0, len(paths), 64):
        patterns = ["".join("[" + character + "]" if character in "*?[" else "[\\\\]" if character == "\\" else character for character in path)
                    for path in paths[offset:offset + 64]]
        result = _run(["/usr/bin/dpkg-query", "--search", "--"] + patterns)
        if result.returncode == 0 or result.stdout:
            return True
        if result.returncode != 1:
            raise ValueError("Cannot establish native package ownership.")
    return False


def _capture(target, root):
    ancestry = _ancestry(os.path.dirname(target), root)
    root_record = next(record for path, record in ancestry if path == root)
    if any(record[-1] != root_record[-1] for path, record in ancestry if path == root or path.startswith(root + "/")):
        raise ValueError("Nested mount points are excluded.")
    tree, paths, logical, allocated = _tree(target, root_record[-1], os.geteuid(), ancestry=ancestry)
    if _package_owned(paths):
        raise ValueError("Native package-owned paths are excluded from cleanup.")
    final_ancestry = _ancestry(os.path.dirname(target), root)
    final_tree, _, _, _ = _tree(target, root_record[-1], os.geteuid(), ancestry=ancestry)
    if final_ancestry != ancestry or final_tree != tree:
        raise ValueError("Target or ancestry changed during native package ownership preflight.")
    return (tuple(final_ancestry), final_tree), logical, allocated


def _report(action, warnings):
    return {"schema_version": 1, "action": action, "status": "rejected", "complete": False,
            "items": [], "plan": None, "warnings": warnings}


def _authorize(report, items, confirm_callback):
    if not items:
        return False
    phrase = ("TRASH" if report["action"] == "cleanup" else "REMOVE") + " " + secrets.token_hex(6)
    report["plan"] = {"action": report["action"], "items": items, "warnings": report["warnings"], "confirmation_phrase": phrase}
    try:
        answer = confirm_callback(report["plan"])
    except EOFError:
        answer = None
    except KeyboardInterrupt:
        report["status"] = "interrupted"
        answer = None
    if type(answer) is not str or answer != phrase:
        if report["status"] != "interrupted":
            report["status"] = "cancelled"
        for item in report["items"]:
            if item["status"] == "planned":
                item["status"] = "cancelled"
        return False
    return True


def _finish(report):
    for item in report["items"]:
        if item["status"] == "planned":
            item.update(status="not_attempted", reason="A previous action was interrupted.")
    successes = {"trashed", "removed"}
    report["complete"] = bool(report["items"]) and all(item["status"] in successes for item in report["items"])
    if report["status"] != "interrupted":
        report["status"] = "complete" if report["complete"] else "partial"
    return report


def cleanup(roots, selections, confirm_callback):
    report = _report("cleanup", [
        "Native Trash moves selected items; allocated space is not freed immediately and reclaimable bytes are unknown.",
        "Native Trash recovery is platform-dependent and is not guaranteed; inspect your Trash before emptying it.",
        "Complete metadata is checked after confirmation; a final pathname check/action race remains. Same-UID hostile processes are outside this protection.",
    ])
    planned = []
    snapshots = {}
    try:
        if os.geteuid() == 0:
            raise ValueError("Cleanup as root is excluded.")
        approved = [_path(root) for root in roots]
        targets = [_path(target) for target in selections]
        if not approved or not targets:
            raise ValueError("Explicit roots and targets are required.")
        for root in approved:
            if root == "/" or any(root == path or root.startswith(path + "/") for path in SYSTEM_PATHS):
                raise ValueError("System scan roots are excluded from cleanup.")
            _ancestry(root, root)
        for index, target in enumerate(targets):
            if any(target == other or target.startswith(other + "/") or other.startswith(target + "/") for other in targets[:index]):
                raise ValueError("Duplicate or overlapping cleanup targets are excluded.")
        _trusted_backend("/usr/bin/gio")
    except (OSError, ValueError) as error:
        report["items"].append({"target": None, "status": "rejected", "reason": str(error) if isinstance(error, ValueError) else "Cannot validate selected roots or native backend."})
        return report
    for target in targets:
        item = {"target": target, "status": "rejected"}
        report["items"].append(item)
        try:
            matching = [root for root in approved if target.startswith(root + "/")]
            if target in approved or not matching:
                raise ValueError("Target must be strictly beneath an approved root.")
            root = max(matching, key=len)
            snapshot, logical, allocated = _capture(target, root)
            snapshots[target] = (root, snapshot)
            planned.append({"target": target, "native_command": ["/usr/bin/gio", "trash", "--", target],
                            "logical_bytes": logical, "allocated_bytes": allocated, "estimated_reclaimable_bytes": None,
                            "recovery": "Native Trash; recovery is not guaranteed."})
            item["status"] = "planned"
        except (OSError, ValueError, subprocess.SubprocessError):
            item["reason"] = "Target is unavailable, outside policy, package-owned, or has incomplete metadata."
    if not _authorize(report, planned, confirm_callback):
        return report
    for item in report["items"]:
        if item["status"] != "planned":
            continue
        target = item["target"]
        root, expected = snapshots[target]
        try:
            actual, _, _ = _capture(target, root)
            if actual != expected:
                raise ValueError("Target or ancestry changed after preview.")
        except KeyboardInterrupt:
            report["status"] = "interrupted"
            break
        except (OSError, ValueError, subprocess.SubprocessError):
            item.update(status="changed", reason="Target or ancestry changed, or metadata could not be revalidated; nothing requested.")
            continue
        try:
            result = _run(["/usr/bin/gio", "trash", "--", target])
            item["returncode"] = result.returncode
            if result.returncode:
                item.update(status="failed", reason="Native Trash returned an error; inspect the original path and Trash.")
            else:
                try:
                    os.lstat(target)
                except FileNotFoundError:
                    item["status"] = "trashed"
                else:
                    item.update(status="uncertain", reason="Native command returned success but the source still exists.")
        except KeyboardInterrupt:
            item.update(status="uncertain", reason="Interrupted native action; inspect source and Trash before any retry.")
            report["status"] = "interrupted"
            break
        except subprocess.TimeoutExpired:
            item.update(status="uncertain", reason="Native action timed out; inspect source and Trash before any retry.")
        except (OSError, ValueError, subprocess.SubprocessError):
            item.update(status="uncertain", reason="Native Trash unavailable or outcome cannot be inspected; no deletion fallback.")
    return _finish(report)


def _package(package_id, admindir):
    command = ["/usr/bin/dpkg-query"]
    if admindir:
        command.append("--admindir=" + admindir)
    command += ["--show", "--showformat=${Package}:${Architecture}\\t${Version}\\t${db:Status-Status}\\t${Essential}\\t${Protected}\\n", package_id]
    result = _run(command)
    if result.returncode == 1 and not result.stdout:
        return None
    lines = result.stdout.splitlines()
    if result.returncode or len(lines) != 1:
        raise ValueError("Native package metadata is incomplete or ambiguous.")
    fields = lines[0].split("\t")
    if len(fields) != 5:
        raise ValueError("Native package metadata is incomplete.")
    identity, version, status_value, essential, protected = fields
    if not PACKAGE_ID.fullmatch(identity) or ":" not in identity or not version or any(ord(character) < 32 for character in version):
        raise ValueError("Native package identity is invalid.")
    if identity != package_id and (":" in package_id or identity.split(":", 1)[0] != package_id):
        raise ValueError("Native package identity differs from selection.")
    if essential not in ("", "no", "yes") or protected not in ("", "no", "yes"):
        raise ValueError("Native package protection metadata is invalid.")
    return {"package_id": identity, "version": version, "status": status_value,
            "essential": essential == "yes", "protected": protected == "yes"}


def _log_state(root):
    path = os.path.join(root, "var/log/dpkg.log")
    ancestry = _ancestry(os.path.dirname(path))
    try:
        metadata = os.stat(path, follow_symlinks=False)
    except FileNotFoundError:
        return tuple(ancestry), None
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid not in (0, os.geteuid()) or metadata.st_mode & 0o022:
        raise ValueError("Alternate root log must be an unwritable-by-others regular file without symlinks.")
    return tuple(ancestry), _identity(metadata, None)


def uninstall(package_ids, confirm_callback, root=None):
    report = _report("uninstall", [
        "Native dpkg removal may run package maintainer scripts and triggers; consequences extend beyond listed package files.",
        "Removal keeps native configuration files where supported. Reinstallation or recovery is not guaranteed; no purge or force is requested.",
        "Dependency checks and database metadata are rechecked after confirmation, but native locking and scripts prevent an atomic preview guarantee.",
        "Installed or reclaimable space cannot be established reliably here; reclaimable bytes are unknown. Existing privileges only; no elevation.",
    ])
    plans = []
    snapshots = {}
    try:
        identifiers = list(package_ids)
        if not identifiers or any(not isinstance(value, str) or not PACKAGE_ID.fullmatch(value) for value in identifiers) or len(set(identifiers)) != len(identifiers):
            raise ValueError("Select distinct exact Debian package identifiers.")
        selected_root = _path(root) if root is not None else None
        if selected_root == "/":
            raise ValueError("Use the default host root or a distinct disposable root.")
        ancestry = _ancestry(selected_root) if selected_root else ()
        log_state = _log_state(selected_root) if selected_root else None
        admindir = os.path.join(selected_root, "var/lib/dpkg") if selected_root else "/var/lib/dpkg"
        database_ancestry = _ancestry(admindir)
        command = ["/usr/bin/dpkg"]
        if selected_root:
            command += ["--root=" + selected_root, "--log=" + os.path.join(selected_root, "var/log/dpkg.log")]
        _trusted_backend("/usr/bin/dpkg")
        _trusted_backend("/usr/bin/dpkg-query")
    except (OSError, ValueError):
        report["items"].append({"target": None, "status": "rejected", "reason": "Package identifiers, root, database, or native backend cannot be validated."})
        return report
    for identifier in identifiers:
        item = {"target": identifier, "status": "rejected"}
        report["items"].append(item)
        try:
            package = _package(identifier, admindir)
            if package is None or package["status"] != "installed" or package["essential"] or package["protected"]:
                raise ValueError("Package is absent, not fully installed, essential, or protected.")
            if any(plan["target"] == package["package_id"] for plan in plans):
                raise ValueError("Repeated canonical package identity.")
            removal = command + ["--remove", package["package_id"]]
            dry_run = _run(command + ["--no-act", "--remove", package["package_id"]])
            if dry_run.returncode:
                raise ValueError("Native dependency or privilege preflight failed.")
            database, _, _, _ = _tree(admindir)
            snapshots[identifier] = (package, database)
            plans.append({"target": package["package_id"], "version": package["version"], "native_command": removal,
                          "estimated_reclaimable_bytes": None, "recovery": "No guaranteed undo; configuration files may remain."})
            item["status"] = "planned"
        except (OSError, ValueError, subprocess.SubprocessError):
            item["reason"] = "Package is protected, incomplete, unavailable, duplicated, or failed native dependency/privilege checks."
    if not _authorize(report, plans, confirm_callback):
        return report
    expected_database = None
    for item in report["items"]:
        if item["status"] != "planned":
            continue
        identifier = item["target"]
        package, database = snapshots[identifier]
        try:
            current_ancestry = _ancestry(selected_root) if selected_root else ()
            current_database, _, _, _ = _tree(admindir)
            if selected_root and _log_state(selected_root) != log_state:
                raise ValueError("Alternate root log ancestry changed after preview.")
            if current_ancestry != ancestry or _ancestry(admindir) != database_ancestry or current_database != (database if expected_database is None else expected_database) or _package(identifier, admindir) != package:
                raise ValueError("Package or database changed after preview.")
            dry_run = _run(command + ["--no-act", "--remove", package["package_id"]])
            if dry_run.returncode or _tree(admindir)[0] != current_database:
                raise ValueError("Native dependency preflight failed or changed the database.")
        except KeyboardInterrupt:
            report["status"] = "interrupted"
            break
        except (OSError, ValueError, subprocess.SubprocessError):
            item.update(status="changed", reason="Package, root, database or native dependency state changed; nothing requested.")
            continue
        try:
            result = _run(command + ["--remove", package["package_id"]])
            item["returncode"] = result.returncode
            after = _package(package["package_id"], admindir)
            expected_database = _tree(admindir)[0]
            if selected_root:
                log_state = _log_state(selected_root)
            if result.returncode:
                item.update(status="failed", reason="Native removal failed or partially completed; inspect package manager state.")
            elif after is None or after["status"] in ("config-files", "not-installed"):
                item["status"] = "removed"
            else:
                item.update(status="uncertain", reason="Native command returned success but removal state is unverified.")
        except KeyboardInterrupt:
            item.update(status="uncertain", reason="Native removal interrupted; inspect package database before any retry.")
            report["status"] = "interrupted"
            break
        except (OSError, ValueError, subprocess.SubprocessError):
            item.update(status="uncertain", reason="Native removal timed out or its outcome cannot be verified; inspect package database before any retry.")
    return _finish(report)
