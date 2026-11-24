package credentials

import "core:testing"

@(test)
pss_certificate_parameters_are_immutable_bounded_metadata :: proc(t: ^testing.T) {
	for c in ([]struct {
			chain:      []u8,
			parameters: Certificate_PSS_Parameters,
		} {
			{
				#load("../../../../tests/core/crypto/tls/credentials/testdata/pss-rsa-chain.pem"),
				{.SHA256, .SHA256, 32},
			},
			{
				#load("../../../../tests/core/crypto/tls/credentials/testdata/pss-salt20-chain.pem"),
				{.SHA256, .SHA256, 20},
			},
			{
				#load("../../../../tests/core/crypto/tls/credentials/testdata/pss-sha384-chain.pem"),
				{.SHA384, .SHA384, 48},
			},
			{
				#load("../../../../tests/core/crypto/tls/credentials/testdata/pss-mgf384-chain.pem"),
				{.SHA256, .SHA384, 32},
			},
		}) {
		a := Audit {
			backing = context.allocator,
		}
		h, e := create(c.chain, fixture_key, {}, audit_allocator(&a))
		testing.expect_value(t, e, .None)
		assert(h != nil)
		before := storage_usage(h)
		p, pe := certificate_pss_parameters(h, 0)
		testing.expect_value(t, pe, .None)
		testing.expect_value(t, p, c.parameters)
		// Returned fields are values, never a view into the immutable owner.
		p.salt_length = 0
		again, _ := certificate_pss_parameters(h, 0)
		testing.expect_value(t, again, c.parameters)
		root, re := certificate_pss_parameters(h, 1)
		testing.expect_value(t, re, .None)
		testing.expect_value(t, root, Certificate_PSS_Parameters{.SHA256, .SHA256, 32})
		_, invalid := certificate_pss_parameters(h, 2)
		testing.expect_value(t, invalid, .Invalid_Index)
		testing.expect_value(t, storage_usage(h), before)
		calls := a.calls
		destroy(&h)
		audit_clean(t, &a)
		for mode in ([]Audit_Mode{.OOM, .Nil_Success, .Undergrant, .Overgrant, .Error_Grant}) {
			for fail_at in 1 ..= calls {
				b := Audit {
					backing = context.allocator,
					mode    = mode,
					fail_at = fail_at,
				}
				bad, be := create(c.chain, fixture_key, {}, audit_allocator(&b))
				testing.expect(t, bad == nil && be == .Allocation_Failed)
				destroy(&bad)
				audit_clean(t, &b)
			}
		}
	}
	_, nil_error := certificate_pss_parameters(nil, 0)
	testing.expect_value(t, nil_error, .Invalid_Handle)
	h, e := create(fixture_cert, fixture_key, {}, context.allocator)
	assert(e == .None)
	defer destroy(&h)
	_, wrong := certificate_pss_parameters(h, 0)
	testing.expect_value(t, wrong, .Unsupported_Signature_Scheme)
	for malformed in ([][]u8 {
			#load("../../../../tests/core/crypto/tls/credentials/testdata/pss-malformed-chain.pem"),
			#load("../../../../tests/core/crypto/tls/credentials/testdata/pss-hash-params-chain.pem"),
			#load("../../../../tests/core/crypto/tls/credentials/testdata/pss-mgf-params-chain.pem"),
		}) {
		a := Audit {
			backing = context.allocator,
		}
		bad, be := create(malformed, fixture_key, {}, audit_allocator(&a))
		testing.expect(t, bad == nil)
		testing.expect_value(t, be, .Malformed_Certificate)
		destroy(&bad)
		audit_clean(t, &a)
	}
}
