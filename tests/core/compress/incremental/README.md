# Incremental decoder reference vectors

`generate_vectors.py` regenerates the positive fixtures using Python standard-library gzip/zlib, independently of
Odin's decoder. The manifest records hashes, sizes and the reference zlib version.
They cover stored/fixed/dynamic DEFLATE, history wrap, gzip optional header fields
and FHCRC, concatenated empty members and corrupt trailers.

`generate_adversarial.py` creates bit-level malformed DEFLATE cases and requires
Python zlib to reject every result before writing the manifest. Run it from any
working directory; it writes only this directory's testdata/raw-invalid-* files.
It does not generate or modify production code.

`generate_brotli_vectors.py` writes `testdata/brotli/`: six inputs (empty, one byte,
text, binary-ish, repetitive, a 240 KiB mix with incompressible and zero runs) compressed
by the reference `brotli` CLI at qualities 0/1/5/9/11 and lgwin 10/16/22, plus a manifest
with hashes and the CLI version. Qualities 0/1 emit WBITS 18 for small lgwin, so the
tests size each window from the stream header. `brotli_incremental_test.odin` checks them
across input/output partitions and work budgets, against `brotli.load`, every truncation
point, trailing bytes, limits, bit flips, and hand-assembled metadata/uncompressed
meta-blocks.

The Odin tests compare complete reference bytes across independent input/output
partitions and work budgets, enforce exact limits and validate terminal errors.
These are finite deterministic tests, not a claim of comprehensive fuzz coverage.

Specifications: [DEFLATE RFC1951](https://www.rfc-editor.org/rfc/rfc1951),
[gzip RFC1952](https://www.rfc-editor.org/rfc/rfc1952),
[Brotli RFC7932](https://www.rfc-editor.org/rfc/rfc7932).
