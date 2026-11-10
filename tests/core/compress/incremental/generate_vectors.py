"""Generate independent deterministic gzip/DEFLATE reference fixtures."""
from pathlib import Path
import gzip
import hashlib
import json
import struct
import zlib

root = Path(__file__).resolve().parent / "testdata"
payload = bytes(range(256)) * 257 + b"abcXYZ12345" * 7000 + b"last-bit"
small = b"hello independent gzip\n"
files = {"payload.bin": payload, "small.bin": small, "empty.bin": b""}
for name, plain in [("dynamic", payload), ("small", small), ("empty", b"")]:
    files[name + ".gz"] = gzip.compress(plain, mtime=0)
for name, level, strategy in [
    ("stored", 0, zlib.Z_DEFAULT_STRATEGY),
    ("fixed", 6, zlib.Z_FIXED),
    ("dynamic", 6, zlib.Z_DEFAULT_STRATEGY),
]:
    encoder = zlib.compressobj(level, zlib.DEFLATED, -15, 8, strategy)
    files[name + ".deflate"] = encoder.compress(payload) + encoder.flush()
header = (b"\x1f\x8b\x08\x1e" + b"\0" * 6 + struct.pack("<H", 7)
          + b"ab\x03\x00xyz" + b"name.txt\0" + b"comment\0")
header += struct.pack("<H", zlib.crc32(header) & 0xffff)
encoder = zlib.compressobj(6, zlib.DEFLATED, -15)
raw = encoder.compress(small) + encoder.flush()
files["optional.gz"] = header + raw + struct.pack("<II", zlib.crc32(small), len(small))
files["concat.gz"] = files["small.gz"] + files["empty.gz"]
files["trailing.gz"] = files["small.gz"] + b"\0"
for key, offset in [("crc", -8), ("size", -4), ("header_crc", len(header) - 1)]:
    corrupt = bytearray(files["optional.gz"])
    corrupt[offset] ^= 1
    files["bad_" + key + ".gz"] = bytes(corrupt)
corrupt = bytearray(files["small.gz"])
corrupt[3] = 0xe0
files["bad_flags.gz"] = bytes(corrupt)
for name, data in files.items():
    (root / name).write_bytes(data)
(root / "manifest.json").write_text(json.dumps({
    "generator": "Python stdlib zlib/gzip, independent of Odin decoder",
    "zlib_version": zlib.ZLIB_VERSION,
    "files": {name: {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
              for name, data in files.items()},
}, indent=2) + "\n")
