package main
import "core:crypto"
import "core:crypto/hash"
import credentials "core:crypto/tls/credentials"
import "core:fmt"
import "core:os"
import "core:thread"

Work :: struct {
	credential: ^credentials.Credential,
	digest:     [32]u8,
	signatures: [8][512]u8,
	length:     int,
	error:      credentials.Error,
}
run :: proc(work: ^Work) {
	for &signature in work.signatures {
		n, error := credentials.sign_digest_pss_sha256(work.credential, work.digest, signature[:])
		if error != .None {
			work.error = error; return
		}
		work.length = n
	}
}
main :: proc() {
	assert(len(os.args) == 4)
	cert, ce := os.read_entire_file(os.args[1], context.allocator); assert(ce == nil)
	defer delete(cert)
	key, ke := os.read_entire_file(os.args[2], context.allocator); assert(ke == nil)
	defer delete(key)
	defer crypto.zero_explicit(raw_data(key), len(key))
	owner, error := credentials.create(cert, key, {}, context.allocator); assert(error == .None)
	defer credentials.destroy(&owner)
	before := credentials.storage_usage(owner)
	fingerprint, fe := credentials.fingerprint(owner); assert(fe == .None)
	jobs: [8]Work
	threads: [8]^thread.Thread
	for &job, i in jobs {
		job.credential = owner
		hash.hash_string_to_buffer(.SHA256, "credential-concurrency-fixture", job.digest[:])
		threads[i] = thread.create_and_start_with_poly_data(&job, run)
		assert(threads[i] != nil)
	}
	for worker in threads {thread.join(worker); thread.destroy(worker)}
	for &job, i in jobs {
		assert(job.error == .None)
		for &signature, j in job.signatures {
			path := fmt.aprintf("%s/%d-%d.sig", os.args[3], i, j)
			assert(os.write_entire_file(path, signature[:job.length]) == nil)
			delete(path)
		}
	}
	after := credentials.storage_usage(owner)
	fingerprint_after, fae := credentials.fingerprint(owner)
	assert(fae == .None && fingerprint == fingerprint_after)
	assert(before == after)
	fmt.printfln(
		"8 workers x8 signatures; retained=%d peak=%d; credential usage/fingerprint unchanged",
		after.retained_bytes,
		after.peak_bytes,
	)
}
