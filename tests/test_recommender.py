"""Tests for the recommendation engine.

Regressions encoded here (all fixed 2026-09-25):
  * "Kyber768" is not a valid post-standardisation name -> must be ML-KEM-768
  * SHA-256 must NOT be recommended for upgrade (false-positive generator)
  * ECC used for key agreement must get a KEM, not a signature scheme
  * AES-256 must not be told to "upgrade" to AES-256
  * every recommendation must carry a rule trace and standard basis
"""

from engine.recommender import get_pqc_recommendation, _normalise_primitive, ML_KEM_SIZES


def _keys(rec):
    assert set(("algorithm", "action", "justification", "tradeoff_latency",
                "tradeoff_size", "rule_trace", "standard_basis", "confidence")) <= set(rec)


def test_no_pre_standardisation_algorithm_names():
    """Kyber / SPHINCS+ / Dilithium are pre-FIPS names; NIST standardised ML-KEM/ML-DSA/SLH-DSA."""
    cases = [
        dict(name="RSA", primitive="pke"),
        dict(name="RSA", primitive="signature"),
        dict(name="ECC", primitive="signature"),
        dict(name="ECDH", primitive="key-agreement"),
        dict(name="AES", primitive="ae", key_length=128),
    ]
    forbidden = ("kyber768", "kyber-768", "dilithium", "sphincs+", "sphincsplus")
    for c in cases:
        rec = get_pqc_recommendation(c)
        low = rec["algorithm"].lower()
        assert not any(f in low for f in forbidden), f"{c} -> {rec['algorithm']}"
        for basis in rec["standard_basis"]:
            assert not any(f in basis.lower() for f in forbidden)


def test_tls_key_exchange_recommends_hybrid_kem():
    rec = get_pqc_recommendation(dict(name="ECDH", primitive="key-agreement", uses="tls"))
    assert "X25519MLKEM768" in rec["algorithm"]
    assert "ML-KEM-768" in rec["algorithm"]
    assert rec["hybrid_semantics"].startswith("Hybrid AND")
    assert "FIPS 203" in " ".join(rec["standard_basis"])
    assert rec["ossification_risk"].startswith("MEDIUM")


def test_hybrid_ands_both_must_be_broken():
    rec = get_pqc_recommendation(dict(name="ECDH", primitive="key-agreement", uses="tls"))
    assert "BOTH" in rec["hybrid_semantics"]


def test_ecc_key_agreement_gets_kem_not_signature_scheme():
    """Regression: every bare 'ECC' hit previously got ML-DSA, including ECDH key exchange."""
    kem = get_pqc_recommendation(dict(name="ECDH", primitive="key-agreement"))
    assert "ML-KEM" in kem["algorithm"]
    assert "ML-DSA" not in kem["algorithm"]


def test_ecdsa_gets_signature_scheme():
    rec = get_pqc_recommendation(dict(name="ECDSA", primitive="signature"))
    assert "ML-DSA" in rec["algorithm"]
    assert "FIPS 204" in " ".join(rec["standard_basis"])


def test_rsa_signature_and_key_transport_differ():
    sig = get_pqc_recommendation(dict(name="RSA", primitive="signature"))
    transport = get_pqc_recommendation(dict(name="RSA", primitive="pke"))
    assert "ML-DSA" in sig["algorithm"]
    assert "ML-KEM" in transport["algorithm"]


def test_kem_recommendation_flags_the_behavioural_change():
    rec = get_pqc_recommendation(dict(name="RSA", primitive="pke"))
    assert "KEM" in rec["justification"] or "encapsulate" in rec["justification"]


def test_sha256_gets_no_action():
    """Regression: SHA-256 was previously upgraded to SHA-384/512 on a false premise."""
    rec = get_pqc_recommendation(dict(name="SHA256", primitive="hash"))
    assert "No migration required" in rec["algorithm"]
    assert rec["action"].lower().startswith("no immediate action")


def test_sha1_is_classical_hygiene_not_quantum():
    rec = get_pqc_recommendation(dict(name="SHA1", primitive="hash"))
    assert "SHA-256" in rec["algorithm"]
    assert "not a quantum one" in rec["justification"]


def test_aes256_no_action():
    rec = get_pqc_recommendation(dict(name="AES", primitive="ae", key_length=256))
    assert "No migration required" in rec["algorithm"]


def test_aes128_is_policy_driven_not_quantum_emergency():
    rec = get_pqc_recommendation(dict(name="AES", primitive="ae", key_length=128))
    assert rec["algorithm"] == "AES-256"
    assert "NOT exposed to harvest-now-decrypt-later" in rec["justification"]


def test_unknown_aes_key_size_asks_for_confirmation():
    rec = get_pqc_recommendation(dict(name="AES", primitive="ae"))
    assert "Confirm" in rec["algorithm"]
    assert rec["confidence"] == "standard-derived"


def test_library_finding_is_a_dependency_not_a_breach():
    rec = get_pqc_recommendation(dict(name="OpenSSL/libcrypto",
                                      primitive="cryptographic-library", type="library"))
    assert "implements" in rec["justification"]
    assert rec["cost_band"] == "LOW"


def test_protocol_and_legacy_cipher_handled():
    tls = get_pqc_recommendation(dict(name="TLS", primitive="protocol"))
    assert "TLS 1.3" in tls["algorithm"]
    legacy = get_pqc_recommendation(dict(name="LEGACY-CIPHER", primitive="protocol"))
    assert "Remove" in legacy["action"]


def test_every_recommendation_is_explainable():
    cases = [
        dict(name="RSA", primitive="pke"),
        dict(name="RSA", primitive="signature"),
        dict(name="ECDH", primitive="key-agreement", uses="tls"),
        dict(name="ECDSA", primitive="signature"),
        dict(name="AES", primitive="ae", key_length=256),
        dict(name="AES", primitive="ae", key_length=128),
        dict(name="SHA256", primitive="hash"),
        dict(name="SHA1", primitive="hash"),
        dict(name="CustomCipher", primitive="mystery"),
    ]
    for c in cases:
        rec = get_pqc_recommendation(c)
        _keys(rec)
        assert rec["rule_trace"], c
        # every recommendation must quantify impact or explicitly declare it not applicable
        assert rec["tradeoff_latency"] and rec["tradeoff_size"], c


def test_unknown_primitive_goes_to_manual_review():
    rec = get_pqc_recommendation(dict(name="CustomCipher"))
    assert "Manual review" in rec["algorithm"]
    assert rec["confidence"] == "manual-review"


def test_size_figures_are_sourced():
    rec = get_pqc_recommendation(dict(name="ECDH", primitive="key-agreement", uses="tls"))
    assert any("Cloudflare" in n for n in rec["notes"])
    assert any("rustls" in n for n in rec["notes"])


def test_normalise_primitive_handles_legacy_strings():
    assert _normalise_primitive("public-key-encryption", "RSA") == "pke"
    assert _normalise_primitive("digital-signature", "RSA") == "signature"
    assert _normalise_primitive("symmetric-encryption", "AES") == "ae"
    assert _normalise_primitive("protocol", "TLS") == "protocol"
    assert _normalise_primitive("cryptographic-library", "libcrypto") == "cryptographic-library"
    assert _normalise_primitive("", "X25519") == "key-agreement"


def test_ml_kem_sizes_match_fips203():
    assert ML_KEM_SIZES["ML-KEM-768"]["ek"] == 1184
    assert ML_KEM_SIZES["ML-KEM-768"]["ct"] == 1088
    assert ML_KEM_SIZES["ML-KEM-512"]["ek"] + ML_KEM_SIZES["ML-KEM-512"]["ct"] == 1568
