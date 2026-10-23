from pathlib import Path


a = Analysis(
    [str(Path(SPECPATH) / "pkg_extractor.py")],
    pathex=[], binaries=[], datas=[], hiddenimports=[], hookspath=[],
    hooksconfig={}, runtime_hooks=[], excludes=["cffi", "pycparser"],
    noarchive=False, optimize=0,
)
required = {"_raw_aes", "_raw_aesni", "_raw_cbc", "_raw_ecb", "_cpuid_c", "_strxor"}
a.binaries = [entry for entry in a.binaries
              if not entry[0].replace("\\", "/").startswith("Crypto/")
              or Path(entry[0]).name.split(".")[0] in required]
found = {Path(entry[0]).name.split(".")[0] for entry in a.binaries
         if entry[0].replace("\\", "/").startswith("Crypto/")}
if found != required:
    raise RuntimeError("Componentes AES esperados não foram encontrados")
pyz = PYZ(a.pure)
exe = EXE(
    pyz, a.scripts, a.binaries, a.datas, [], name="easy-pkg-extractor",
    debug=False, strip=False, upx=False, runtime_tmpdir=None, console=False,
    cdict={},
)
