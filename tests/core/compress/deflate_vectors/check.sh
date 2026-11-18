#!/bin/sh
# Decodes the gzip members written by generate.odin with the system gzip and
# compares each with the payload they were compressed from.
set -eu
here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
payload=$here/../incremental/testdata/payload.bin

if ! command -v gzip >/dev/null 2>&1; then
    printf 'gzip not found: vectors not checked\n' >&2
    exit 0
fi

status=0
for vector in "$here"/*.gz; do
    if gzip -dc < "$vector" | cmp -s - "$payload"; then
        printf 'ok   %s\n' "$(basename -- "$vector")"
    else
        printf 'FAIL %s\n' "$(basename -- "$vector")"
        status=1
    fi
done
exit "$status"
