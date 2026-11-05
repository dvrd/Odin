package tls


import "core:crypto/x509"
import "core:encoding/pem"
import "core:io"
import "core:mem"
import "core:os"
import "core:slice"

MAX_ROOT_CERTIFICATES :: 512
MAX_ROOT_BUNDLE_SIZE :: 4 << 20

Root_Error_Kind :: enum {
	None,
	Invalid_State,
	Read_Failed,
	Bundle_Oversized,
	Invalid_PEM,
	Invalid_Certificate,
	No_Certificates,
	Certificate_Limit,
	Allocation_Failed,
}
Root_Error :: struct {
	kind:        Root_Error_Kind,
	io:          os.Error,
	certificate: x509.Error,
	pem:         pem.Error,
	allocation:  mem.Allocator_Error,
}

// Keep the pool at a stable address while TLS Config.root_cas refers to it.
// Certificates borrow DER owned by the PEM blocks. Destroy after all clients.
Root_Pool :: struct {
	certificates: [MAX_ROOT_CERTIFICATES]x509.Certificate,
	roots:        [MAX_ROOT_CERTIFICATES]^x509.Certificate,
	blocks:       [MAX_ROOT_CERTIFICATES]^pem.Block,
	count:        int,
	allocator:    mem.Allocator,
}

root_pool_destroy :: proc(pool: ^Root_Pool) {
	if pool == nil do return

	for i in 0 ..< pool.count {
		x509.destroy(&pool.certificates[i], pool.allocator)
		pem.block_delete(pool.blocks[i])
	}
	pool^ = {}
}

root_pool_parse :: proc(
	pool: ^Root_Pool,
	data: []u8,
	allocator := context.allocator,
) -> Root_Error {
	if pool == nil || pool.allocator.procedure != nil {
		return {kind = .Invalid_State}
	}

	if len(data) > MAX_ROOT_BUNDLE_SIZE {
		return {kind = .Bundle_Oversized}
	}

	pool.allocator = allocator
	success := false
	defer if !success do root_pool_destroy(pool)

	rest := data
	for len(rest) > 0 {
		block, remaining, err := pem.decode(rest, allocator)
		if err != nil {
			return {kind = .Invalid_PEM, pem = err}
		}

		if block == nil do break

		rest = remaining
		if block.label != "CERTIFICATE" {
			pem.block_delete(block)
			continue
		}

		if pool.count == MAX_ROOT_CERTIFICATES {
			pem.block_delete(block)
			return {kind = .Certificate_Limit}
		}

		cert, parse_err := x509.parse(pem.block_bytes(block), allocator)
		if parse_err != .None {
			pem.block_delete(block)
			return {kind = .Invalid_Certificate, certificate = parse_err}
		}

		i := pool.count
		pool.certificates[i] = cert
		pool.roots[i] = &pool.certificates[i]
		pool.blocks[i] = block
		pool.count += 1
	}
	if pool.count == 0 do return {kind = .No_Certificates}

	success = true
	return {}
}

root_pool_load_file :: proc(pool: ^Root_Pool, path: string) -> Root_Error {
	if pool == nil || pool.allocator.procedure != nil {
		return {kind = .Invalid_State}
	}

	file, open_err := os.open(path)
	if open_err != nil {
		return {kind = .Read_Failed, io = open_err}
	}

	defer os.close(file)
	data, allocation_err := make([]u8, MAX_ROOT_BUNDLE_SIZE + 1)
	if allocation_err != nil {
		return {kind = .Allocation_Failed, allocation = allocation_err}
	}

	defer delete(data)
	used := 0
	for used < len(data) {
		n, err := os.read(file, data[used:])
		used += n
		if !slice.contains([]type_of(err){nil, io.Error.EOF}, err) {
			return {kind = .Read_Failed, io = err}
		}

		if n == 0 || err == io.Error.EOF do break
	}
	if used > MAX_ROOT_BUNDLE_SIZE {
		return {kind = .Bundle_Oversized}
	}

	return root_pool_parse(pool, data[:used])
}

// Uses the platform's conventional PEM bundle, without shell commands or a
// bundled frozen CA list. An explicit application path can use load_file.
root_pool_load_system :: proc(pool: ^Root_Pool) -> Root_Error {
	paths := [?]string {
		"/etc/ssl/certs/ca-certificates.crt",
		"/etc/ssl/cert.pem",
		"/etc/pki/tls/certs/ca-bundle.crt",
		"/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
	}
	last: Root_Error = {
		kind = .Read_Failed,
	}
	for path in paths {
		err := root_pool_load_file(pool, path)
		if err.kind == .None do return {}

		if err.kind != .Read_Failed do return err

		last = err
	}
	return last
}
