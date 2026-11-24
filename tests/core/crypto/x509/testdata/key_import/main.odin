package main
import "core:bytes"
import "core:crypto"
import "core:crypto/rsa"
import "core:crypto/x509"
import "core:fmt"
import "core:mem"
import "core:os"
import google "shared:google"

read_owned :: proc(path: string) -> []u8 {
	data, error := os.read_entire_file(path, context.allocator)
	assert(error == nil)
	return data
}

Counting :: struct {
	calls:   int,
	backing: mem.Allocator,
}

count_allocate :: proc(
	data: rawptr,
	mode: mem.Allocator_Mode,
	size, alignment: int,
	old_memory: rawptr,
	old_size: int,
	location := #caller_location,
) -> (
	[]u8,
	mem.Allocator_Error,
) {
	state := cast(^Counting)data
	if mode == .Alloc || mode == .Alloc_Non_Zeroed || mode == .Resize || mode == .Resize_Non_Zeroed {
		state.calls += 1
	}
	return state.backing.procedure(state.backing.data, mode, size, alignment, old_memory, old_size, location)
}

main :: proc() {
	assert(len(os.args) == 2)
	directory := os.args[1]
	key := new(rsa.Private_Key)
	defer free(key)
	defer rsa.private_key_clear(key)
	message := transmute([]u8)string("native RSA import interoperability\n")
	for bits in ([?]int{1024, 2048, 4096}) {
		path := fmt.aprintf("%s/rsa%d.der", directory, bits)
		data := read_owned(path)
		delete(path)
		previous := context
		counter := Counting {
			backing = context.allocator,
		}
		context.allocator = {
			procedure = count_allocate,
			data      = &counter,
		}
		context.temp_allocator = context.allocator
		failure := x509.parse_pkcs8_rsa(key, data)
		context = previous
		assert(failure.kind == .None && counter.calls == 0)
		crypto.zero_explicit(raw_data(data), len(data))
		delete(data)
		// The native key must be independent of erased input storage.
		assert(rsa.private_key_size(key) == bits / 8)
		signature: [512]u8
		assert(rsa.sign_pkcs1(key, .SHA256, message, signature[:bits / 8]))
		path = fmt.aprintf("%s/rsa%d.pkcs1.sig", directory, bits)
		assert(os.write_entire_file(path, signature[:bits / 8]) == nil)
		delete(path)
		assert(rsa.sign_pss(key, .SHA256, 32, message, signature[:bits / 8], mgf1_algo = .SHA256))
		path = fmt.aprintf("%s/rsa%d.pss.sig", directory, bits)
		assert(os.write_entire_file(path, signature[:bits / 8]) == nil)
		delete(path)
		fmt.println("RSA", bits, "import allocation_calls", counter.calls)
	}
	fresh := new(rsa.Private_Key)
	defer free(fresh)
	defer rsa.private_key_clear(fresh)
	path := fmt.aprintf("%s/rsa1024.der", directory)
	data := read_owned(path)
	delete(path)
	assert(x509.parse_pkcs8_rsa(fresh, data).kind == .None)
	assert(x509.parse_pkcs8_rsa(key, data).kind == .None) // Replaces4096-bit key.
	crypto.zero_explicit(raw_data(data), len(data))
	delete(data)
	assert(bytes.equal((cast([^]u8)key)[:size_of(rsa.Private_Key)], (cast([^]u8)fresh)[:size_of(rsa.Private_Key)]))
	google_key := new(rsa.Private_Key)
	defer free(google_key)
	defer rsa.private_key_clear(google_key)
	old := new(rsa.Private_Key)
	defer free(old)
	defer rsa.private_key_clear(old)
	path = fmt.aprintf("%s/rsa2048.pem", directory)
	data = read_owned(path)
	delete(path)
	assert(google.service_key_decode(google_key, string(data)).kind == .None)
	crypto.zero_explicit(raw_data(data), len(data))
	delete(data)
	rsa.private_key_set(old, google_key)
	path = fmt.aprintf("%s/rsa1024.pem", directory)
	data = read_owned(path)
	delete(path)
	assert(google.service_key_decode(google_key, string(data)).kind == .Invalid_Private_Key)
	crypto.zero_explicit(raw_data(data), len(data))
	delete(data)
	assert(rsa.private_key_equal(google_key, old))
	for item in ([]struct {
			name: string,
			kind: x509.Private_Key_Error_Kind,
		}{{"encrypted.der", .Unsupported_Profile}, {"multiprime.der", .Unsupported_Version}}) {
		path = fmt.aprintf("%s/%s", directory, item.name)
		data = read_owned(path)
		delete(path)
		assert(x509.parse_pkcs8_rsa(key, data).kind == item.kind)
		crypto.zero_explicit(raw_data(data), len(data))
		delete(data)
		assert(rsa.private_key_equal(key, fresh))
	}
	rsa.private_key_clear(key)
	for b in (cast([^]u8)key)[:size_of(rsa.Private_Key)] {assert(b == 0)}
	fmt.println(
		"4096→1024 replacement matches fresh key; Google small-key rejection preserves old key; explicit clear erased",
		size_of(rsa.Private_Key),
		"bytes",
	)
}
