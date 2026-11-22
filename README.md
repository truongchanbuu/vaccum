# Vaccum

Vaccum is a Linux CLI for scanning selected directories, reviewing installed
packages, making conservative folder-organization proposals, and preparing an
optional local AI handoff. Scanning and reporting work without an AI provider.
Cleanup and uninstall require explicit interactive confirmation; scans and AI
recommendations never modify files.

## Support

The verified release target is Ubuntu 26.04 with Python 3.14.4 and the Python
standard library. Other Linux distributions and Python versions are unverified.
The `apps` and `uninstall` commands use the native dpkg database; cleanup uses
the platform trash through `gio`. Snap, Flatpak, and other package backends are
not included.

## Download the release

Download `v0.1.0` from
`https://github.com/truongchanbuu/vaccum/releases/tag/v0.1.0` and verify the
Python zipapp with:

```sh
gh release download v0.1.0 --repo truongchanbuu/vaccum \
  --pattern 'vaccum-0.1.0.pyz' --pattern SHA256SUMS
sha256sum -c SHA256SUMS
python3 -B vaccum-0.1.0.pyz --help
```

The `.pyz` requires Python 3 on Linux. It is not a native executable and does
not bundle an interpreter. These commands assume the release and its assets
are available; remote download availability is not independently verified here.

## Quickstart

Roots are always explicit; there are no implicit scan locations. Use a test
folder first:

```sh
test_root="$(mktemp -d)"
printf 'example\n' > "$test_root/example.txt"
python3 -B vaccum-0.1.0.pyz scan "$test_root" --format json
rm "$test_root/example.txt"
rmdir "$test_root"
```

For a source checkout, run `python3 -B vaccum.py` in place of
`python3 -B vaccum-0.1.0.pyz`.

```sh
python3 -B vaccum.py --help
python3 -B vaccum.py scan /path/to/test-folder --format json
python3 -B vaccum.py apps --format json
python3 -B vaccum.py recommend /path/to/test-folder --format json
python3 -B vaccum.py ai-report /path/to/test-folder
```

The AI report is local and provider-neutral. It is anonymized by default;
exact paths require explicit `--include-paths`. Review what you share with an
external agent before sending it.

## Review and actions

```sh
python3 -B vaccum.py cleanup ROOT --target ROOT/item --format human
python3 -B vaccum.py uninstall PACKAGE --format human
```

These commands preview exact targets. `--apply` requires an interactive prompt
and the exact random confirmation phrase shown by the preview; there is no
automatic cleanup, `--yes`, sudo, purge, or cascade mode. Targets are
revalidated before action. Protected system/package-owned paths, roots,
symlinks, mounts, special files, overlaps, and untrusted writable paths are
rejected. Native trash may not free storage immediately, and recovery depends
on the platform. Uninstall may run package maintainer scripts; configuration
may remain and undo is not guaranteed.

## Reports and safety

Reports identify paths or package identities, categories, reasons, uncertainty,
suggested actions, measured sizes where available, and skipped or inaccessible
locations. Age or a temporary-looking name alone does not prove that something
is safe to delete. Logical and allocated file sizes are reported separately;
hardlinks are deduplicated, and reclaimable space is unknown rather than
guaranteed. The scanner does not read file contents when metadata is
sufficient, rejects symlink traversal outside approved roots, skips special
files, and reports partial results when permissions or changing paths prevent
complete inspection. Filesystem access can update access times.

Exit status is 0 for complete results under the explicit skip policy, 1 for an
incomplete or depth-limited result, 2 for command-usage errors, and 130 when
interrupted. The native gio pathname check/action is not atomic against a
malicious same-UID actor, and scanning or capture is not atomic.

## Development

No third-party dependencies are required. Run the tests and build the zipapp
from a source checkout with:

```sh
python3 -B -m unittest discover -s tests -v
python3 -B scripts/build_release.py
```

The build writes `dist/vaccum-0.1.0.pyz` and `dist/SHA256SUMS`. Native tests
also require the host's `gio` and `dpkg` helpers and an environment permitting
unprivileged Linux namespaces. Broader platform support, direct AI adapters,
automated folder moves, and a desktop UI remain outside this release.
