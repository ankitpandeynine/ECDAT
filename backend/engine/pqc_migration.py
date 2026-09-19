"""Role-specific upgrade targets. A KEM is never a signature replacement."""
FIPS = {'kem': 'https://csrc.nist.gov/pubs/fips/203/final',
        'signature': 'https://csrc.nist.gov/pubs/fips/204/final',
        'alternative_signature': 'https://csrc.nist.gov/pubs/fips/205/final'}


def crypto_migration(tls, findings):
    rows = []
    seen = set()
    def add(current, role, target, why, evidence, action, validation, reference=None):
        key = (current, role)
        if key in seen: return
        seen.add(key)
        rows.append({'current': current, 'role': role, 'target': target, 'reason': why,
                     'evidence': evidence, 'action': action, 'validation': validation,
                     'reference': reference, 'status': 'review_required'})
    pq = tls.get('post_quantum') or {}
    supported = pq.get('supported_groups') or []
    add(', '.join(supported) if supported else 'TLS key establishment — no hybrid success recorded',
        'TLS key establishment', 'TLS 1.3 with X25519MLKEM768 (hybrid X25519 + ML-KEM-768)',
        'Protect session key establishment against the quantum threat while retaining a classical component.',
        pq.get('reason', 'Older scan: rescan to measure hybrid key exchange.'),
        ('Retain the measured hybrid group; verify client coverage and separately review certificate authentication.' if supported else
         'Upgrade the TLS terminator to a vendor-supported hybrid implementation (for OpenSSL, 3.5+), enable the group, and stage client compatibility tests. Configure the CDN/edge and origin independently.'),
        'Rescan for a successful explicit hybrid handshake; test ordinary clients and record which connection leg was tested.', FIPS['kem'])
    cert = tls.get('certificate') or {}
    key = cert.get('public_key', '')
    if any(x in key.upper() for x in ('RSA', 'EC', 'ED25519', 'ED448', 'DSA')):
        add(key, 'Certificate authentication / signatures', 'ML-DSA; SLH-DSA where appropriate and supported',
            'Classical certificate signatures remain a separate quantum-exposed dependency even with hybrid key exchange.',
            'Observed leaf certificate public key: ' + key,
            'Inventory CA, trust stores, client, HSM and protocol support. Use a supported PQ signature profile in a controlled environment; do not replace a public Web PKI certificate with an incompatible algorithm.',
            'Validate the whole trust chain and signatures in every required client. Hybrid TLS alone does not pass this check.', FIPS['signature'])
    elif pq:
        # Certificate could not be inspected (e.g. server only accepts the PQC group, blocking the Python SSL
        # default handshake), but the certificate authentication path still requires independent migration.
        # A hybrid KEX observation is NOT evidence that the certificate signature is PQ-safe.
        add('Certificate public key — not inspectable in this scan', 'Certificate authentication / signatures',
            'ML-DSA; SLH-DSA where appropriate and supported',
            'Certificate authentication is a separate quantum-exposed dependency from key exchange. '
            'Hybrid key exchange does not protect certificate signature trust chains.',
            'Certificate public key could not be observed during this scan (likely due to cipher/group restrictions). '
            'Inspect the certificate separately to determine the current signature algorithm.',
            'Obtain the certificate separately and inspect the public key algorithm. '
            'Inventory CA, trust stores, client, HSM and protocol support before migrating.',
            'Validate the whole trust chain and signatures in every required client. '
            'Hybrid TLS handshake success does not constitute a certificate signature check.', FIPS['signature'])
    for f in findings:
        primitive = str(f.get('primitive', 'Unknown'))
        p = primitive.upper()
        evidence = f"{f.get('file', 'artifact')}:{f.get('line', f.get('offset', '?'))} • scan {f.get('scan_id', '?')} • {f.get('confidence', 'unrated')} confidence"
        if any(x in p for x in ('ML-KEM', 'MLKEM', 'ML-DSA', 'SLH-DSA')):
            continue
        if any(x in p for x in ('RSA', 'ECDH', 'X25519', 'DIFFIE', 'DH-')):
            add(primitive, 'Key establishment (confirm usage)', 'ML-KEM-768 via a supported protocol; hybrid transition where available',
                'RSA/DH/ECDH key establishment is vulnerable to a sufficiently capable quantum computer.', evidence,
                'Confirm this is encryption/key agreement, not signing. Replace the protocol/provider integration; ML-KEM establishes a shared secret and is not a drop-in bulk-data encryption API.',
                'Test encapsulation/decapsulation, interoperability, error handling, key serialization and downstream authenticated encryption.', FIPS['kem'])
        if any(x in p for x in ('RSA', 'ECDSA', 'ED25519', 'ED448', 'DSA')):
            add(primitive, 'Digital signatures (confirm usage)', 'ML-DSA; SLH-DSA as a hash-based alternative',
                'Quantum-safe signing needs a signature algorithm, not ML-KEM.', evidence,
                'Confirm signing usage, choose a vendor-supported security level, rotate signing keys and version signature formats; account for larger keys and signatures.',
                'Verify valid/invalid signatures, old/new format handling, trust distribution and rollback compatibility.', FIPS['signature'])
        if 'AES' in p:
            add(primitive, 'Symmetric encryption', 'AES-256 with an appropriate authenticated mode and sound key management',
                'Symmetric encryption is not replaced by ML-KEM or ML-DSA. Review key strength, mode and nonce handling separately.', evidence,
                'Retain suitable AES-256 deployments; otherwise assess key-size and mode changes. Do not infer key size or mode from a binary constant.',
                'Verify actual key size, authenticated mode, nonce uniqueness, rotation and interoperability.')
        if any(x in p for x in ('MD5', 'SHA-1', 'SHA1', 'DES', 'RC4')):
            add(primitive, 'Legacy cryptography remediation', 'SHA-256/384 for hashes; AES-256 authenticated encryption for legacy ciphers',
                'This is existing cryptographic weakness remediation, separate from public-key PQ migration.', evidence,
                'Confirm the purpose before replacing the primitive; password hashing, message authentication and encryption require different APIs.',
                'Run purpose-specific security and compatibility tests; do not treat a renamed algorithm as a completed migration.')
        if len(rows) >= 40:
            break
    return {'status': 'draft', 'tls_key_exchange': pq, 'upgrades': rows,
            'scope': 'Classical-to-post-quantum key establishment and signatures, plus separate symmetric/legacy remediation.',
            'limitations': ['Algorithm targets are candidate migration paths, not verified drop-in replacements.',
                           'A scan cannot establish application-wide quantum safety or vendor/client compatibility.',
                           'Finding role must be confirmed; RSA may be used for signing, encryption, or both.'],
            'references': [{'title': 'NIST FIPS 203: ML-KEM', 'url': FIPS['kem']},
                           {'title': 'NIST FIPS 204: ML-DSA', 'url': FIPS['signature']},
                           {'title': 'NIST FIPS 205: SLH-DSA', 'url': FIPS['alternative_signature']}]}
