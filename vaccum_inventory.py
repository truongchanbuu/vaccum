import os
import re
import stat
import subprocess


DPKG_QUERY = "/usr/bin/dpkg-query"
PACKAGE = re.compile(r"[a-z0-9][a-z0-9+.-]+\Z")
ARCHITECTURE = re.compile(r"[a-z0-9][a-z0-9-]*\Z")
VERSION = re.compile(r"[0-9][A-Za-z0-9.+:~\-]*\Z")


def inventory(admindir=None):
    report = {
        "schema_version": 1,
        "status": "complete",
        "complete": True,
        "backend": "dpkg-query",
        "scope": "Installed Debian packages recorded by dpkg; packages are not equivalent to desktop applications. Snap, Flatpak and unmanaged applications are not covered.",
        "database": os.path.abspath(os.fspath(admindir)) if admindir is not None else "/var/lib/dpkg",
        "installed_packages": [],
        "errors": [],
    }

    def error(code, reason):
        report["complete"] = False
        report["status"] = "partial"
        report["errors"].append({"code": code, "reason": reason})

    command = [DPKG_QUERY, "--no-pager", "--show",
               "--showformat=${Status}\t${Package}\t${Version}\t${Architecture}\t${Installed-Size}\n"]
    if admindir is not None:
        if not os.fspath(admindir) or "\0" in os.fspath(admindir):
            error("invalid_database", "An explicit database directory must be a nonempty valid path.")
            return report
        command.append("--admindir=" + report["database"])
    try:
        executable = os.stat(DPKG_QUERY)
        if not stat.S_ISREG(executable.st_mode) or executable.st_uid != 0 or executable.st_mode & 0o022:
            error("backend_unavailable", "The supported trusted dpkg-query executable is unavailable.")
            return report
        result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, text=True, encoding="utf-8", errors="replace",
                                timeout=10, cwd="/", env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "LANG": "C"})
        output = result.stdout
        if result.returncode:
            error("query_failed", "Native package inventory returned an unsuccessful exit status.")
    except subprocess.TimeoutExpired as timeout:
        error("query_timeout", "Package inventory timed out; no complete result is available.")
        output = timeout.output or ""
        if isinstance(output, bytes):
            output = output.decode("utf-8", errors="replace")
        output = output.rpartition("\n")[0]
    except OSError:
        error("backend_unavailable", "Cannot query the supported native package database.")
        return report
    except KeyboardInterrupt:
        report["status"] = "interrupted"
        report["complete"] = False
        return report
    seen = set()
    malformed = 0
    for line in output.splitlines():
        fields = line.split("\t")
        if len(fields) != 5:
            malformed += 1
            continue
        status, package, version, architecture, size = fields
        state = status.split()
        if len(state) != 3:
            malformed += 1
            continue
        if state[2] != "installed":
            continue
        identity = package + ":" + architecture
        if (state[1] != "ok" or not PACKAGE.fullmatch(package) or not VERSION.fullmatch(version)
                or not ARCHITECTURE.fullmatch(architecture) or (size and not re.fullmatch(r"[0-9]{1,15}", size))
                or identity in seen):
            malformed += 1
            continue
        seen.add(identity)
        report["installed_packages"].append({
            "package_id": identity,
            "package": package,
            "architecture": architecture,
            "version": version,
            "category": "installed-package",
            "estimated_installed_bytes": int(size) * 1024 if size else None,
            "estimated_reclaimable_bytes": None,
            "reason": "The native dpkg database records this package as installed.",
            "uncertainty": "Package metadata does not establish whether software is unused. Installed-Size is a KiB estimate, not measured disk usage or guaranteed recovery; dependencies and shared data may remain.",
            "suggested_action": "Review package purpose and native uninstall consequences before approving any action.",
        })
    if malformed:
        error("malformed_records", f"Excluded {malformed} invalid or duplicate package records.")
    return report
