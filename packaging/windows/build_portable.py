#!/usr/bin/env python3
"""Build the self-contained TraceQuarry portable bundle for 64-bit Windows.

The bundle needs no Python installation on the target machine. It contains the
official CPython Windows runtime (the python.org build published on NuGet), the
runtime wheels, the TraceQuarry sources and resources, and small native
launchers. The build itself runs on Linux or Windows and needs:

  * CPython with the same minor version as the bundled runtime (bytecode magic)
  * pip (to download Windows wheels)
  * x86_64-w64-mingw32-gcc and x86_64-w64-mingw32-windres (launchers)

Usage: python3.12 packaging/windows/build_portable.py [--out dist]
"""

from __future__ import annotations

import argparse
import hashlib
import py_compile
import shutil
import subprocess
import sys
import tomllib
import urllib.request
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
PYTHON_VERSION = "3.12.10"
PYTHON_NUPKG_SHA256 = "0eb85c2dfccccf1b17352de4c397f69194035b7d37149eacc16f1147d93de3b8"
NUPKG_URL = (
    "https://api.nuget.org/v3-flatcontainer/python/"
    f"{PYTHON_VERSION}/python.{PYTHON_VERSION}.nupkg"
)
# tzdata: Windows has no system IANA time-zone database.
# zstandard: Zstandard-compressed fields in native systemd journal files.
EXTRA_WHEELS = ("tzdata==2025.2", "zstandard==0.25.0")

STDLIB_EXCLUDED_DIRS = {
    "__pycache__", "ensurepip", "idlelib", "lib2to3", "pydoc_data", "site-packages",
    "test", "tkinter", "turtledemo", "venv",
}
STDLIB_EXCLUDED_FILES = {"turtle.py", "pydoc.py", "doctest.py"}
DLL_EXCLUDED_PREFIXES = ("_test", "_ctypes_test", "_tkinter", "tcl", "tk", "xxlimited", "zlib1")
MODE = py_compile.PycInvalidationMode.UNCHECKED_HASH


def run(*command: str | Path) -> None:
    subprocess.run([str(part) for part in command], check=True)


def fetch_runtime(cache: Path, nupkg: Path | None, verify: bool) -> Path:
    target = nupkg or cache / f"python.{PYTHON_VERSION}.nupkg"
    if not target.exists():
        cache.mkdir(parents=True, exist_ok=True)
        print(f"Downloading {NUPKG_URL}")
        with urllib.request.urlopen(NUPKG_URL) as response:  # noqa: S310 - fixed https URL
            target.write_bytes(response.read())
    digest = hashlib.sha256(target.read_bytes()).hexdigest()
    print(f"python nupkg sha256: {digest}")
    if verify and digest != PYTHON_NUPKG_SHA256:
        raise SystemExit(f"Unexpected Python runtime digest for {target}")
    return target


def build_stdlib_zip(lib_dir: Path, archive: Path, scratch: Path) -> None:
    """Pack the standard library as bytecode-only, like the embeddable CPython."""
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as bundle:
        for path in sorted(lib_dir.rglob("*")):
            relative = path.relative_to(lib_dir)
            if not path.is_file() or STDLIB_EXCLUDED_DIRS.intersection(relative.parts):
                continue
            if len(relative.parts) == 1 and relative.name in STDLIB_EXCLUDED_FILES:
                continue
            if path.suffix == ".py":
                compiled = scratch / relative.with_suffix(".pyc")
                compiled.parent.mkdir(parents=True, exist_ok=True)
                py_compile.compile(
                    str(path), cfile=str(compiled), dfile=f"Lib/{relative.as_posix()}",
                    doraise=True, optimize=0, invalidation_mode=MODE,
                )
                bundle.write(compiled, relative.with_suffix(".pyc").as_posix())
            elif path.suffix != ".pyc":
                bundle.write(path, relative.as_posix())


def precompile_tree(tree: Path) -> None:
    for path in sorted(tree.rglob("*.py")):
        py_compile.compile(str(path), doraise=True, invalidation_mode=MODE)


def copy_tree(source: Path, target: Path) -> None:
    shutil.copytree(
        source, target, ignore=shutil.ignore_patterns("__pycache__", "*.pyc", ".DS_Store")
    )


def build_launchers(stage: Path, scratch: Path, version: str) -> None:
    numeric = ([int(p) for p in "".join(c if c.isdigit() else " " for c in version).split()]
               + [0, 0, 0, 0])[:4]
    resource = scratch / "launcher.rc"
    resource.write_text(
        f'''1 ICON "{(HERE / "tracequarry.ico").as_posix()}"
1 VERSIONINFO
FILEVERSION {",".join(map(str, numeric))}
PRODUCTVERSION {",".join(map(str, numeric))}
BEGIN
  BLOCK "StringFileInfo"
  BEGIN
    BLOCK "040904B0"
    BEGIN
      VALUE "CompanyName", "Chill Ethical People"
      VALUE "FileDescription", "TraceQuarry portable launcher"
      VALUE "FileVersion", "{version}"
      VALUE "ProductName", "TraceQuarry"
      VALUE "ProductVersion", "{version}"
      VALUE "LegalCopyright", "Apache-2.0"
    END
  END
  BLOCK "VarFileInfo"
  BEGIN
    VALUE "Translation", 0x409, 1200
  END
END
''',
        encoding="ascii",
    )
    compiled_resource = scratch / "launcher.res.o"
    run("x86_64-w64-mingw32-windres", resource, "-O", "coff", "-o", compiled_resource)
    for name, script, pause in (
        ("TraceQuarry.exe", "launcher.py", 1),
        ("tracequarry-cli.exe", "cli.py", 0),
    ):
        run(
            "x86_64-w64-mingw32-gcc", "-O2", "-s", "-municode", "-Wall",
            f'-DTQ_SCRIPT=L"{script}"', f"-DTQ_PAUSE_ON_ERROR={pause}",
            HERE / "launcher.c", compiled_resource, "-o", stage / name,
        )


def build(out_dir: Path, nupkg: Path | None, verify: bool) -> Path:
    if sys.version_info[:2] != tuple(int(p) for p in PYTHON_VERSION.split(".")[:2]):
        raise SystemExit(f"Run this build with Python {PYTHON_VERSION.rsplit('.', 1)[0]}.")
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    version = project["version"]
    cache = out_dir / "cache"
    scratch = out_dir / "scratch"
    stage = out_dir / f"TraceQuarry-{version}-win64"
    for path in (scratch, stage):
        shutil.rmtree(path, ignore_errors=True)
        path.mkdir(parents=True)

    # 1. Official CPython runtime.
    with zipfile.ZipFile(fetch_runtime(cache, nupkg, verify)) as package:
        package.extractall(scratch / "nupkg")
    tools = scratch / "nupkg" / "tools"
    runtime = stage / "runtime"
    runtime.mkdir()
    for name in ("python.exe", "python3.dll", "python312.dll", "vcruntime140.dll",
                 "vcruntime140_1.dll", "LICENSE.txt"):
        shutil.copy2(tools / name, runtime / name)
    (runtime / "DLLs").mkdir()
    for path in sorted((tools / "DLLs").iterdir()):
        if path.is_file() and path.suffix in {".pyd", ".dll"} and not path.name.startswith(
            DLL_EXCLUDED_PREFIXES
        ):
            shutil.copy2(path, runtime / "DLLs" / path.name)
    build_stdlib_zip(tools / "Lib", runtime / "python312.zip", scratch / "stdlib")
    # A ._pth file makes the runtime fully isolated from any installed Python,
    # the registry, PYTHONPATH/PYTHONHOME and the user's site-packages.
    (runtime / "python312._pth").write_text(
        "python312.zip\nDLLs\nLib\\site-packages\n..\\app\n", encoding="ascii"
    )

    # 2. Third-party wheels for win_amd64.
    wheels = scratch / "wheels"
    run(
        sys.executable, "-m", "pip", "download", "--quiet", "--only-binary=:all:",
        "--platform", "win_amd64", "--python-version", "3.12", "--implementation", "cp",
        "--no-deps", "--dest", wheels, "--requirement", ROOT / "requirements.txt",
        *EXTRA_WHEELS,
    )
    site_packages = runtime / "Lib" / "site-packages"
    site_packages.mkdir(parents=True)
    for wheel in sorted(wheels.glob("*.whl")):
        with zipfile.ZipFile(wheel) as archive:
            archive.extractall(site_packages)
    shutil.rmtree(site_packages / "bin", ignore_errors=True)
    precompile_tree(site_packages)

    # 3. Application.
    app = stage / "app"
    app.mkdir()
    for name in ("uac_parser", "rules", "assets", "web"):
        copy_tree(ROOT / name, app / name)
    for name in ("launcher.py", "cli.py"):
        shutil.copy2(HERE / name, app / name)
    precompile_tree(app)

    # 4. Launchers, documentation and licenses.
    build_launchers(stage, scratch, version)
    (stage / "evidence").mkdir()
    (stage / "evidence" / "README.txt").write_text(
        "Put evidence here (or anywhere under your user profile) to load it by path.\r\n",
        encoding="ascii",
    )
    shutil.copy2(HERE / "README-Windows.md", stage / "README-Windows.md")
    licenses = stage / "licenses"
    licenses.mkdir()
    for name in ("LICENSE", "NOTICE", "OWNERSHIP.md"):
        shutil.copy2(ROOT / name, licenses / name)
    shutil.move(runtime / "LICENSE.txt", licenses / "PYTHON-LICENSE.txt")

    # 5. Archive.
    archive_path = out_dir / f"{stage.name}.zip"
    archive_path.unlink(missing_ok=True)
    with zipfile.ZipFile(archive_path, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as bundle:
        for path in sorted(stage.rglob("*")):
            relative = Path(stage.name) / path.relative_to(stage)
            if path.is_dir():
                bundle.writestr(relative.as_posix() + "/", "")
            else:
                bundle.write(path, relative.as_posix())
    shutil.rmtree(scratch)
    digest = hashlib.sha256(archive_path.read_bytes()).hexdigest()
    (out_dir / f"{archive_path.name}.sha256").write_text(
        f"{digest}  {archive_path.name}\n", encoding="ascii"
    )
    print(f"Built {archive_path} ({archive_path.stat().st_size / 1e6:.1f} MB)\nsha256 {digest}")
    return archive_path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", type=Path, default=ROOT / "dist" / "windows")
    parser.add_argument("--python-nupkg", type=Path, help="Use a local python NuGet package")
    parser.add_argument("--skip-runtime-verify", action="store_true",
                        help="Do not pin the Python runtime digest")
    args = parser.parse_args()
    build(args.out.resolve(), args.python_nupkg, not args.skip_runtime_verify)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
