"""Generate deterministic Brotli reference fixtures with the reference `brotli` CLI.

Writes testdata/brotli/<input>.bin and <input>.q<quality>.w<lgwin>.br, plus a
manifest with hashes and the encoder version. Independent of Odin's decoder.
"""
from pathlib import Path
import hashlib
import json
import random
import subprocess

root = Path(__file__).resolve().parent / "testdata" / "brotli"
root.mkdir(parents=True, exist_ok=True)
rng = random.Random(7932)

words = ("the of and to in is that for it as was with be by on not he this are or his from at which but have an had "
         "they you were their one all we can her has there been if more when will would who so no information "
         "about international development government language computer system between through during before "
         "Café Привет 日本語").split()


def text(size):
    out = []
    n = 0
    while n < size:
        word = rng.choice(words)
        if rng.random() < 0.1:
            word = word.capitalize()
        if rng.random() < 0.05:
            word = word.upper()
        word += rng.choice([" ", " ", " ", ", ", ". ", "\n"])
        out.append(word)
        n += len(word.encode())
    return "".join(out).encode()[:size]


def binary(size):
    out = bytearray()
    while len(out) < size:
        out += bytes([rng.randrange(256) for _ in range(rng.randrange(1, 8))])
        out += bytes([out[-1]]) * rng.randrange(0, 12)
        if len(out) > 40 and rng.random() < 0.3:
            start = rng.randrange(len(out) - 32)
            out += out[start:start + rng.randrange(4, 32)]
    return bytes(out[:size])


large = (text(70000) + binary(30000) + b"abcabcabd" * 4000 + bytes(rng.randrange(256) for _ in range(20000))
         + text(60000) + bytes(30000))
inputs = {
    "empty": b"",
    "one": b"Q",
    "text": text(6000),
    "binary": binary(3000),
    "repeat": b"0123456789abcdef" * 4096,
    "large": large,
}
version = subprocess.run(["brotli", "--version"], check=True, capture_output=True, text=True).stdout.strip()
manifest = {"generator": version, "streams": {}}
for name, plain in inputs.items():
    (root / (name + ".bin")).write_bytes(plain)
    for quality in (0, 1, 5, 9, 11):
        for lgwin in (10, 16, 22):
            wire = subprocess.run(["brotli", "-c", "-q", str(quality), f"--lgwin={lgwin}"], input=plain, check=True,
                                  capture_output=True).stdout
            stem = f"{name}.q{quality}.w{lgwin}.br"
            (root / stem).write_bytes(wire)
            manifest["streams"][stem] = {"bytes": len(wire), "plain": len(plain),
                                         "sha256": hashlib.sha256(wire).hexdigest()}
(root / "manifest.json").write_text(json.dumps(manifest, indent=1, sort_keys=True) + "\n")
