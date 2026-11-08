package main
import "core:crypto"
import credentials "../../../../../../../core/crypto/tls/credentials"
import "core:fmt"
import "core:os"
import "core:thread"

Work :: struct {
	credential: ^credentials.Credential,
	scheme: credentials.Signature_Scheme,
	signatures: [8][512]u8,
	length: [8]int,
	error:      credentials.Error,
}
run :: proc(work: ^Work) {
	for &signature,i in work.signatures {
		n, error := credentials.sign_sha256(work.credential, work.scheme, transmute([]u8)string("credential-concurrency-fixture"), signature[:])
		if error != .None {
			work.error = error; return
		}
		work.length[i] = n
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
		job.scheme = credentials.signature_scheme(owner)
		threads[i] = thread.create_and_start_with_poly_data(&job, run)
		assert(threads[i] != nil)
	}
	for worker in threads {thread.join(worker); thread.destroy(worker)}
	for &job, i in jobs {
		assert(job.error == .None)
		for &signature, j in job.signatures {
			path := fmt.aprintf("%s/%d-%d.sig", os.args[3], i, j)
			assert(os.write_entire_file(path, signature[:job.length[j]]) == nil)
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
