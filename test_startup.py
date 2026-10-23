import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

import pkg_extractor as pkg


ROOT = Path(__file__).resolve().parent
EXECUTABLE = ROOT / ".release" / "onefile-dist" / "easy-pkg-extractor.exe"
if not EXECUTABLE.is_file():
    EXECUTABLE = ROOT / "easy-pkg-extractor.exe"


class StartupTests(unittest.TestCase):
    @unittest.skipIf(pkg.AES is None, "Componente AES indisponível")
    def test_aes_modes_with_and_without_processor_acceleration(self):
        key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
        plain = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a")
        iv = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        for accelerated in (False, True):
            with self.subTest(accelerated=accelerated):
                self.assertEqual(pkg.AES.new(key, pkg.AES.MODE_ECB, use_aesni=accelerated).encrypt(plain).hex(),
                                 "3ad77bb40d7a3660a89ecaf32466ef97")
                self.assertEqual(pkg.AES.new(key, pkg.AES.MODE_CBC, iv, use_aesni=accelerated).encrypt(plain).hex(),
                                 "7649abac8119b246cee98e9b12e9197d")

    @unittest.skipUnless(sys.platform == "win32" and pkg.AES is not None, "Criptografia Windows indisponível")
    def test_fallback_xts_matches_windows_for_high_sectors_and_partial_blocks(self):
        tweak_key, data_key = bytes(range(16)), bytes(range(16, 32))
        try:
            native = pkg._WindowsXts(data_key + tweak_key)
        except (OSError, AttributeError) as error:
            self.skipTest(str(error))
        try:
            extractor = pkg.PkgExtractor("unused.pkg", "unused-output")
            extractor.ecb_tweak = pkg.AES.new(tweak_key, pkg.AES.MODE_ECB, use_aesni=False)
            extractor.ecb_data = pkg.AES.new(data_key, pkg.AES.MODE_ECB, use_aesni=False)
            raw = bytes(range(256)) * 32
            for sector in (0, 7, 1 << 40):
                with self.subTest(sector=sector):
                    expected = native.decrypt(raw, sector)
                    self.assertEqual(extractor._xts_decrypt(raw, sector), expected)
                    self.assertEqual(extractor._xts_decrypt(raw[:4112], sector), expected[:4112])
        finally:
            native._cleanup()

    @unittest.skipUnless(sys.platform == "win32" and pkg.tk is not None, "Janela Windows indisponível")
    def test_window_buttons_and_automatic_scan_remain_usable(self):
        with tempfile.TemporaryDirectory(dir=ROOT, prefix="startup-test-") as folder:
            invalid = Path(folder) / "nested" / "invalid.pkg"
            invalid.parent.mkdir()
            invalid.write_bytes(b"invalid")
            root = pkg.tk.Tk()
            root.withdraw()
            destroyed = []
            root.bind("<Destroy>", lambda event: destroyed.append(True) if event.widget == root else None)
            with mock.patch.object(pkg, "_application_directory", return_value=Path(folder)):
                app = pkg.App(root)
                try:
                    deadline = time.monotonic() + 5
                    while app._status_message[0] != "no_packages" and time.monotonic() < deadline:
                        root.update()
                        time.sleep(0.005)
                    self.assertEqual(app._status_message[0], "no_packages")
                    self.assertFalse(app.is_scanning)
                    self.assertIn("invalid.pkg", app.txt.get("1.0", "end"))
                    self.assertEqual(app.language, "en")
                    app.btn_language.invoke()
                    self.assertEqual(app.language, "pt")
                    app.btn_language.invoke()
                    self.assertEqual(app.language, "en")
                    self.assertEqual(app.entry_dest.get(), folder)
                    self.assertEqual(str(app.btn_add_files.cget("state")), "normal")
                finally:
                    app.close()
                    deadline = time.monotonic() + 5
                    while not destroyed and time.monotonic() < deadline:
                        root.update()
                        time.sleep(0.005)
                    self.assertTrue(destroyed)

    @unittest.skipUnless(EXECUTABLE.is_file(), "Executável não compilado")
    def test_executable_starts_without_python_path_and_rejects_invalid_input(self):
        executable = EXECUTABLE
        with tempfile.TemporaryDirectory(dir=ROOT, prefix="startup-test-") as folder:
            directory = Path(folder)
            invalid = directory / "invalid.pkg"
            invalid.write_bytes(b"invalid")
            environment = dict(os.environ, TEMP=folder, TMP=folder)
            environment.pop("PYTHONHOME", None)
            environment.pop("PYTHONPATH", None)
            if sys.platform == "win32":
                environment["PATH"] = os.path.join(os.environ["WINDIR"], "System32")
            result = subprocess.run([str(executable), "--no-gui"], env=environment,
                                    capture_output=True, timeout=15)
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertIn(b"easy-pkg-extractor.exe", result.stderr)
            result = subprocess.run([str(executable), "--no-gui", str(invalid), str(directory / "output")],
                                    env=environment, capture_output=True, timeout=15)
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertFalse((directory / "output").exists())
            self.assertFalse(list(directory.glob("_MEI*")))


if __name__ == "__main__":
    unittest.main()
