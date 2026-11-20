import io
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from uac_parser.loaders.archive import load_input
from uac_parser.loaders.uac_layout import discover_exclusions, discover_sources


class ArchiveTests(unittest.TestCase):
    def test_loose_evidence_file_is_copied_into_isolated_root(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "auth.log.1.gz"
            source.write_bytes(b"not-compressed-test-evidence\n")

            loaded = load_input(str(source))
            try:
                copied = loaded.root / source.name
                self.assertTrue(copied.is_file())
                self.assertEqual(copied.read_bytes(), source.read_bytes())
                self.assertNotEqual(copied.parent, source.parent)
            finally:
                loaded.cleanup()

    def test_invalid_named_archive_is_not_treated_as_a_loose_log(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "collection.tar.gz"
            source.write_text("not an archive")

            with self.assertRaisesRegex(ValueError, "archive name but is not valid"):
                load_input(str(source))

    def test_tar_regular_file_is_streamed_into_canonical_root(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "valid.tar.gz"
            with tarfile.open(archive, "w:gz") as handle:
                member = tarfile.TarInfo("collection/var/log/auth.log")
                payload = b"synthetic auth event\n"
                member.size = len(payload)
                handle.addfile(member, io.BytesIO(payload))

            loaded = load_input(str(archive))
            try:
                extracted = loaded.root / "var/log/auth.log"
                self.assertEqual(extracted.read_bytes(), payload)
                self.assertTrue(
                    extracted.resolve().is_relative_to(loaded.root.resolve())
                )
            finally:
                loaded.cleanup()

    def test_mixed_root_archive_keeps_every_top_level_member_in_scope(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "mixed-root.tar"
            with tarfile.open(archive, "w") as handle:
                for name, payload in (
                    ("collection/var/log/auth.log", b"nested event\n"),
                    ("collection-manifest.txt", b"manifest\n"),
                ):
                    member = tarfile.TarInfo(name)
                    member.size = len(payload)
                    handle.addfile(member, io.BytesIO(payload))

            loaded = load_input(str(archive))
            try:
                self.assertEqual(loaded.member_prefix, "")
                self.assertTrue((loaded.root / "collection/var/log/auth.log").is_file())
                self.assertTrue((loaded.root / "collection-manifest.txt").is_file())
            finally:
                loaded.cleanup()

    def test_archive_uses_configured_scratch_volume(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = root / "valid.tar.gz"
            scratch = root / "scratch"
            with tarfile.open(archive, "w:gz") as handle:
                member = tarfile.TarInfo("collection/var/log/auth.log")
                payload = b"synthetic auth event\n"
                member.size = len(payload)
                handle.addfile(member, io.BytesIO(payload))

            loaded = load_input(str(archive), temp_parent=scratch)
            try:
                self.assertTrue(loaded.root.resolve().is_relative_to(scratch.resolve()))
            finally:
                loaded.cleanup()

    def test_archive_rejects_insufficient_expansion_space(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "valid.tar.gz"
            with tarfile.open(archive, "w:gz") as handle:
                member = tarfile.TarInfo("collection/var/log/auth.log")
                payload = b"synthetic auth event\n"
                member.size = len(payload)
                handle.addfile(member, io.BytesIO(payload))

            with (
                patch(
                    "uac_parser.loaders.archive.shutil.disk_usage",
                    return_value=SimpleNamespace(free=0),
                ),
                self.assertRaisesRegex(ValueError, "Insufficient free disk space"),
            ):
                load_input(str(archive))

    def test_tar_path_traversal_is_rejected(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "unsafe.tar.gz"
            with tarfile.open(archive, "w:gz") as handle:
                member = tarfile.TarInfo("../outside.txt")
                payload = b"unsafe"
                member.size = len(payload)
                handle.addfile(member, io.BytesIO(payload))

            with self.assertRaisesRegex(ValueError, "escapes extraction root"):
                load_input(str(archive))

    def test_tar_links_are_not_materialized(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "links.tar.gz"
            with tarfile.open(archive, "w:gz") as handle:
                member = tarfile.TarInfo("evidence-link")
                member.type = tarfile.SYMTYPE
                member.linkname = "/etc/passwd"
                handle.addfile(member)

            loaded = load_input(str(archive))
            try:
                self.assertFalse((loaded.root / "evidence-link").exists())
                exclusion = (loaded.archive_exclusions or [])[0]
                self.assertEqual(exclusion["relative"], "evidence-link")
                self.assertEqual(exclusion["member_type"], "symlink")
                self.assertEqual(exclusion["link_target"], "/etc/passwd")
                self.assertEqual(exclusion["byte_size"], len("/etc/passwd"))
                self.assertEqual(len(exclusion["sha256"]), 64)
            finally:
                loaded.cleanup()

    def test_zip_path_traversal_is_rejected(self) -> None:
        with self.subTest("zip traversal"):
            import tempfile

            with tempfile.TemporaryDirectory() as directory:
                archive = Path(directory) / "unsafe.zip"
                with zipfile.ZipFile(archive, "w") as handle:
                    handle.writestr("../outside.txt", "unsafe")

                with self.assertRaisesRegex(ValueError, "escapes extraction root"):
                    load_input(str(archive))

    def test_zip_symlink_is_not_materialized(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "links.zip"
            with zipfile.ZipFile(archive, "w") as handle:
                member = zipfile.ZipInfo("evidence-link")
                member.create_system = 3
                member.external_attr = 0o120777 << 16
                handle.writestr(member, "/etc/passwd")

            loaded = load_input(str(archive))
            try:
                self.assertFalse((loaded.root / "evidence-link").exists())
                exclusion = (loaded.archive_exclusions or [])[0]
                self.assertEqual(exclusion["relative"], "evidence-link")
                self.assertEqual(exclusion["member_type"], "symlink")
                self.assertEqual(exclusion["link_target"], "/etc/passwd")
                self.assertEqual(exclusion["byte_size"], len("/etc/passwd"))
                self.assertEqual(len(exclusion["sha256"]), 64)
            finally:
                loaded.cleanup()

    def test_missing_input_has_clear_error(self) -> None:
        import tempfile

        with (
            tempfile.TemporaryDirectory() as directory,
            self.assertRaisesRegex(ValueError, "Input does not exist"),
        ):
            load_input(str(Path(directory) / "missing.tar.gz"))

    def test_macos_metadata_is_excluded_and_audited(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "bodyfile.txt").write_text("0|/tmp/a|1|0|0|0|0|1|1|1|1\n")
            (root / "._bodyfile.txt").write_text("AppleDouble metadata")
            (root / "__MACOSX").mkdir()
            (root / "__MACOSX" / "bodyfile.txt").write_text("metadata copy")

            sources = discover_sources(root)
            exclusions = discover_exclusions(root)

            self.assertTrue(sources)
            self.assertTrue(
                all(
                    "._" not in source.relative and "__MACOSX" not in source.relative
                    for source in sources
                )
            )
            self.assertEqual(
                {item["relative"] for item in exclusions},
                {"._bodyfile.txt", "__MACOSX/bodyfile.txt"},
            )


class WindowsExtractionTests(unittest.TestCase):
    def test_extended_length_paths(self) -> None:
        from unittest import mock

        from uac_parser.loaders import archive as module

        with mock.patch.object(module.os.path, "abspath", lambda value: value):
            self.assertEqual(
                module.extended_length_path("C:\\cases\\out"), "\\\\?\\C:\\cases\\out"
            )
            self.assertEqual(
                module.extended_length_path("\\\\?\\C:\\cases"), "\\\\?\\C:\\cases"
            )
            self.assertEqual(
                module.extended_length_path("\\\\nas\\share\\x"),
                "\\\\?\\UNC\\nas\\share\\x",
            )

    def test_member_names_are_made_safe_for_windows_only(self) -> None:
        from uac_parser.loaders.archive import _MemberNamer

        name = "[root]/dev/disk/by-path/pci-0000:00:1f.2-ata-1"
        self.assertEqual(_MemberNamer(windows=False).local_name(name), name)
        namer = _MemberNamer(windows=True)
        self.assertEqual(
            namer.local_name(name), "[root]/dev/disk/by-path/pci-0000%3A00%3A1f.2-ata-1"
        )
        self.assertEqual(namer.local_name("a/what?*.txt"), "a/what%3F%2A.txt")
        self.assertEqual(namer.local_name("a/tab\tname"), "a/tab%09name")
        # Stable for repeated lookups, and names differing only by case stay apart.
        self.assertEqual(namer.local_name("etc/Makefile"), "etc/Makefile")
        self.assertEqual(namer.local_name("etc/makefile"), "etc/makefile.~case1")
        self.assertEqual(namer.local_name("etc/makefile"), "etc/makefile.~case1")
        self.assertEqual(namer.local_name("ETC/x"), "ETC.~case1/x")
        self.assertEqual(namer.local_name("etc/Makefile/child"), "etc/Makefile/child")

    def test_windows_naming_extracts_colliding_and_invalid_names(self) -> None:
        import io
        import tarfile
        import tempfile
        from pathlib import Path
        from unittest import mock

        from uac_parser.loaders import archive as module

        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "collection.tar"
            with tarfile.open(source, "w") as bundle:
                for name, body in (
                    ("c/var/log/a:b.log", b"colon"),
                    ("c/etc/Readme", b"upper"),
                    ("c/etc/readme", b"lower"),
                ):
                    info = tarfile.TarInfo(name)
                    info.size = len(body)
                    bundle.addfile(info, io.BytesIO(body))
            original = module._MemberNamer

            with mock.patch.object(
                module, "_MemberNamer", lambda: original(windows=True)
            ):
                loaded = module.load_input(str(source))
            try:
                files = {
                    path.relative_to(loaded.root).as_posix(): path.read_bytes()
                    for path in loaded.root.rglob("*")
                    if path.is_file()
                }
            finally:
                loaded.cleanup()

        self.assertEqual(
            files,
            {
                "var/log/a%3Ab.log": b"colon",
                "etc/Readme": b"upper",
                "etc/readme.~case1": b"lower",
            },
        )

    def test_one_unwritable_member_is_reported_not_fatal(self) -> None:
        import io
        import tarfile
        import tempfile
        from pathlib import Path

        from uac_parser.loaders.archive import load_input

        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "collection.tar"
            with tarfile.open(source, "w") as bundle:
                for name, body in (
                    ("c/good.log", b"kept"),
                    ("c/" + "n" * 300, b"name longer than any filesystem allows"),
                    ("c/also-good.log", b"kept too"),
                ):
                    info = tarfile.TarInfo(name)
                    info.size = len(body)
                    bundle.addfile(info, io.BytesIO(body))

            loaded = load_input(str(source))
            try:
                names = sorted(p.name for p in loaded.root.rglob("*") if p.is_file())
                failures = [
                    item
                    for item in loaded.archive_exclusions or []
                    if item["reason"] == "archive_member_extraction_failed"
                ]
            finally:
                loaded.cleanup()

        self.assertEqual(names, ["also-good.log", "good.log"])
        self.assertEqual(len(failures), 1)
        self.assertTrue(failures[0]["relative"].startswith("c/nnn"))
        self.assertIn("OSError", failures[0]["error"])
