# Incremental decoder reference vectors

`generate_vectors.py` regenerates the positive fixtures using Python standard-library gzip/zlib, independently of
Odin's decoder. The manifest records hashes, sizes and the reference zlib version.
They cover stored/fixed/dynamic DEFLATE, history wrap, gzip optional header fields
and FHCRC, concatenated empty members and corrupt trailers.

`generate_adversarial.py` creates bit-level malformed DEFLATE cases and requires
Python zlib to reject every result before writing the manifest. Run it from any
working directory; it writes only this directory's testdata/raw-invalid-* files.
It does not generate or modify production code.

The Odin tests compare complete reference bytes across independent input/output
partitions and work budgets, enforce exact limits and validate terminal errors.
These are finite deterministic tests, not a claim of comprehensive fuzz coverage.

Specifications: [DEFLATE RFC1951](https://www.rfc-editor.org/rfc/rfc1951),
[gzip RFC1952](https://www.rfc-editor.org/rfc/rfc1952).
