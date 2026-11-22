import hashlib
from pathlib import Path
import tempfile
import zipapp


ROOT = Path(__file__).resolve().parents[1]
SOURCES = ("vaccum.py", "vaccum_actions.py", "vaccum_analysis.py", "vaccum_inventory.py")


def build_release(output_dir=None):
    output = Path(output_dir) if output_dir is not None else ROOT / "dist"
    output.mkdir(parents=True, exist_ok=True)
    archive = output / "vaccum-0.1.0.pyz"
    with tempfile.TemporaryDirectory() as directory:
        staging = Path(directory)
        for name in SOURCES:
            (staging / name).write_bytes((ROOT / name).read_bytes())
        (staging / "__main__.py").write_text("import sys\nfrom vaccum import main\n\nsys.exit(main())\n", encoding="utf-8")
        zipapp.create_archive(staging, target=archive, interpreter="/usr/bin/env python3", compressed=True)
    checksum = output / "SHA256SUMS"
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    checksum.write_text(f"{digest}  {archive.name}\n", encoding="utf-8")
    return archive, checksum


if __name__ == "__main__":
    for path in build_release():
        print(path)
