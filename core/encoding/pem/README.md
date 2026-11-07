# PEM decoded-buffer ownership (OKAMI-148)

`decode` borrows encoded input and returns an owning `Block`. It retains the
existing signature and byte/label decoding behavior. The caller releases the
Block with `block_delete`, which uses its captured allocator.

Decoded PEM can hold private keys. The decoder validates the armor first and
sizes the decoded backing exactly once, so no growth step can release a stale
copy through an allocator's ordinary resize. There is no generic PEM input cap.
Applications must retain their own input and decoded-size limits.

Allocation failure releases everything the decoder owns.
This includes allocators returning nil with no error: Block, data and
label allocations are checked. No partial owning Block is
returned on failure. `block_delete` wipes full decoded capacity, including spare
bytes, before asking the allocator to free it. Input bytes are not mutated.

These guarantees apply to owned backing storage. They cannot erase external
aliases, encoded caller input, compiler/register copies or a caller's persistent
files. The allocator controls whether a free physically releases storage.

The regression audit forces relocation and inspects owned buffers immediately
before free, including poisoned spare capacity. The old decoder exposed four
dirty releases in that test. It also covers every allocation failure as both
Out_Of_Memory and nil,nil, malformed final boundaries, nil allocators and existing
certificate/CMS decoding tests.

```sh
./odin test tests/core/encoding/pem -thread-count:1 -warnings-as-errors \
  -sanitize:address -define:ODIN_TEST_THREADS=1 -define:ODIN_TEST_FAIL_ON_BAD_MEMORY=true
```
