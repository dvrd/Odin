#+build darwin
package tls

import CF "core:sys/darwin/CoreFoundation"
import Sec "core:sys/darwin/Security"

// Copies system anchors into the pool. SecTrustEvaluate is intentionally not
// used: the TLS verifier keeps doing the certificate and hostname checks.
// A certificate this parser cannot represent is skipped. An explicit ca_file
// never reaches this path.
root_pool_load_darwin :: proc(pool: ^Root_Pool) -> Root_Error {
	if pool == nil || pool.count != 0 || pool.allocator.procedure != nil {
		return {kind = .Invalid_State}
	}
	if root_pool_load_anchor_certificates(pool) && pool.count > 0 {
		return {}
	}
	if pool.count == 0 && root_pool_load_system_keychain(pool) && pool.count > 0 {
		return {}
	}
	if pool.count == 0 {
		return {kind = .No_Certificates}
	}
	return {}
}

@(private)
root_pool_consume_certificates :: proc(pool: ^Root_Pool, certificates: CF.ArrayRef) -> bool {
	if certificates == nil {
		return false
	}
	defer CF.Release(cast(CF.TypeRef)certificates)
	count := int(CF.ArrayGetCount(certificates))
	admitted := false
	for i in 0 ..< count {
		if pool.count == MAX_ROOT_CERTIFICATES {
			break
		}
		item := CF.ArrayGetValueAtIndex(certificates, CF.Index(i))
		if item == nil {
			continue
		}
		certificate := cast(Sec.SecCertificateRef)item
		der := Sec.SecCertificateCopyData(certificate)
		if der == nil {
			continue
		}
		length := int(CF.DataGetLength(der))
		pointer := CF.DataGetBytePtr(der)
		if pointer != nil && length > 0 {
			bytes := ([^]u8)(rawptr(pointer))[:length]
			if root_pool_add_der(pool, bytes).kind == .None {
				admitted = true
			}
		}
		CF.Release(cast(CF.TypeRef)der)
	}
	return admitted
}

@(private)
root_pool_load_anchor_certificates :: proc(pool: ^Root_Pool) -> bool {
	anchors: CF.ArrayRef
	status := Sec.SecTrustCopyAnchorCertificates(&anchors)
	if status != 0 {
		return false
	}
	return root_pool_consume_certificates(pool, anchors)
}

@(private)
root_pool_load_system_keychain :: proc(pool: ^Root_Pool) -> bool {
	keychain: Sec.SecKeychainRef
	opened := Sec.SecKeychainOpen(
		"/System/Library/Keychains/SystemRootCertificates.keychain",
		&keychain,
	)
	if opened != 0 || keychain == nil {
		return false
	}
	defer CF.Release(cast(CF.TypeRef)keychain)
	query := CF.DictionaryCreateMutable(
		nil,
		0,
		&CF.kTypeDictionaryKeyCallBacks,
		&CF.kTypeDictionaryValueCallBacks,
	)
	if query == nil {
		return false
	}
	defer CF.Release(cast(CF.TypeRef)query)
	keychain_value := rawptr(keychain)
	search_list := CF.ArrayCreate(nil, &keychain_value, 1, &CF.kTypeArrayCallBacks)
	if search_list == nil {
		return false
	}
	defer CF.Release(cast(CF.TypeRef)search_list)
	CF.DictionarySetValue(query, rawptr(Sec.kSecClass), rawptr(Sec.kSecClassCertificate))
	CF.DictionarySetValue(query, rawptr(Sec.kSecMatchLimit), rawptr(Sec.kSecMatchLimitAll))
	CF.DictionarySetValue(query, rawptr(Sec.kSecReturnRef), rawptr(CF.kBooleanTrue))
	CF.DictionarySetValue(query, rawptr(Sec.kSecMatchSearchList), rawptr(search_list))
	matched: CF.TypeRef
	status := Sec.SecItemCopyMatching(query, &matched)
	if status != 0 || matched == nil {
		return false
	}
	if CF.GetTypeID(matched) != CF.ArrayGetTypeID() {
		CF.Release(matched)
		return false
	}
	return root_pool_consume_certificates(pool, cast(CF.ArrayRef)matched)
}
