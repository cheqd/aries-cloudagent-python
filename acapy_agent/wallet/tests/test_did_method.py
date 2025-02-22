from unittest import TestCase

from ..key_type import (
    BLS12381G1,
    BLS12381G1G2,
    BLS12381G2,
    ED25519,
    P256,
    X25519,
    KeyTypes,
)

ED25519_PREFIX_BYTES = b"\xed\x01"
BLS12381G1_PREFIX_BYTES = b"\xea\x01"
BLS12381G1G2_PREFIX_BYTES = b"\xee\x01"
BLS12381G2_PREFIX_BYTES = b"\xeb\x01"
X25519_PREFIX_BYTES = b"\xec\x01"
P256_PREFIX_BYTES = b"\x80\x24"

ED25519_KEY_NAME = "ed25519"
X25519_KEY_NAME = "x25519"
P256_KEY_NAME = "p256"
BLS12381G1_KEY_NAME = "bls12381g1"
BLS12381G2_KEY_NAME = "bls12381g2"
BLS12381G1G2_KEY_NAME = "bls12381g1g2"

ED25519_MULTICODEC_NAME = "ed25519-pub"
X25519_MULTICODEC_NAME = "x25519-pub"
P256_MULTICODEC_NAME = "p256-pub"
BLS12381G1_MULTICODEC_NAME = "bls12_381-g1-pub"
BLS12381G2_MULTICODEC_NAME = "bls12_381-g2-pub"
BLS12381G1G2_MULTICODEC_NAME = "bls12_381-g1g2-pub"

ED25519_JWS_ALG = "EdDSA"
X25519_JWS_ALG = None
P256_JWS_ALG = "ES256"
BLS12381G1_JWS_ALG = None
BLS12381G2_JWS_ALG = None
BLS12381G1G2_JWS_ALG = None


class TestKeyType(TestCase):
    def test_from_multicodec_name(self):
        key_types = KeyTypes()
        assert key_types.from_multicodec_name(ED25519_MULTICODEC_NAME) == ED25519
        assert key_types.from_multicodec_name(X25519_MULTICODEC_NAME) == X25519
        assert key_types.from_multicodec_name(P256_MULTICODEC_NAME) == P256
        assert key_types.from_multicodec_name(BLS12381G1_MULTICODEC_NAME) == BLS12381G1
        assert key_types.from_multicodec_name(BLS12381G2_MULTICODEC_NAME) == BLS12381G2
        assert (
            key_types.from_multicodec_name(BLS12381G1G2_MULTICODEC_NAME) == BLS12381G1G2
        )
        assert key_types.from_multicodec_name("non-existing") is None

    def test_from_key_type(self):
        key_types = KeyTypes()
        assert key_types.from_key_type(ED25519_KEY_NAME) == ED25519
        assert key_types.from_key_type(X25519_KEY_NAME) == X25519
        assert key_types.from_key_type(P256_KEY_NAME) == P256
        assert key_types.from_key_type(BLS12381G1_KEY_NAME) == BLS12381G1
        assert key_types.from_key_type(BLS12381G2_KEY_NAME) == BLS12381G2
        assert key_types.from_key_type(BLS12381G1G2_KEY_NAME) == BLS12381G1G2
        assert key_types.from_key_type("non-existing") is None

    def test_from_multicodec_prefix(self):
        key_types = KeyTypes()
        assert key_types.from_multicodec_prefix(ED25519_PREFIX_BYTES) == ED25519
        assert key_types.from_multicodec_prefix(X25519_PREFIX_BYTES) == X25519
        assert key_types.from_multicodec_prefix(P256_PREFIX_BYTES) == P256
        assert key_types.from_multicodec_prefix(BLS12381G1_PREFIX_BYTES) == BLS12381G1
        assert key_types.from_multicodec_prefix(BLS12381G2_PREFIX_BYTES) == BLS12381G2
        assert key_types.from_multicodec_prefix(BLS12381G1G2_PREFIX_BYTES) == BLS12381G1G2
        assert key_types.from_multicodec_prefix(b"\xef\x01") is None

    def test_from_prefixed_bytes(self):
        key_types = KeyTypes()
        assert (
            key_types.from_prefixed_bytes(
                b"".join([ED25519_PREFIX_BYTES, b"random-bytes"])
            )
            == ED25519
        )
        assert (
            key_types.from_prefixed_bytes(
                b"".join([X25519_PREFIX_BYTES, b"random-bytes"])
            )
            == X25519
        )
        assert (
            key_types.from_prefixed_bytes(b"".join([P256_PREFIX_BYTES, b"random-bytes"]))
            == P256
        )
        assert (
            key_types.from_prefixed_bytes(
                b"".join([BLS12381G1_PREFIX_BYTES, b"random-bytes"])
            )
            == BLS12381G1
        )
        assert (
            key_types.from_prefixed_bytes(
                b"".join([BLS12381G2_PREFIX_BYTES, b"random-bytes"])
            )
            == BLS12381G2
        )
        assert (
            key_types.from_prefixed_bytes(
                b"".join([BLS12381G1G2_PREFIX_BYTES, b"random-bytes"])
            )
            == BLS12381G1G2
        )
        assert (
            key_types.from_prefixed_bytes(b"".join([b"\xef\x01", b"other-random-bytes"]))
            is None
        )

    def test_properties(self):
        key_type = ED25519

        assert key_type.key_type == ED25519_KEY_NAME
        assert key_type.multicodec_name == ED25519_MULTICODEC_NAME
        assert key_type.multicodec_prefix == ED25519_PREFIX_BYTES
        assert key_type.jws_algorithm == ED25519_JWS_ALG

        key_type = X25519

        assert key_type.key_type == X25519_KEY_NAME
        assert key_type.multicodec_name == X25519_MULTICODEC_NAME
        assert key_type.multicodec_prefix == X25519_PREFIX_BYTES
        assert key_type.jws_algorithm == X25519_JWS_ALG

        key_type = P256

        assert key_type.key_type == P256_KEY_NAME
        assert key_type.multicodec_name == P256_MULTICODEC_NAME
        assert key_type.multicodec_prefix == P256_PREFIX_BYTES
        assert key_type.jws_algorithm == P256_JWS_ALG

        key_type = BLS12381G1

        assert key_type.key_type == BLS12381G1_KEY_NAME
        assert key_type.multicodec_name == BLS12381G1_MULTICODEC_NAME
        assert key_type.multicodec_prefix == BLS12381G1_PREFIX_BYTES
        assert key_type.jws_algorithm == BLS12381G1_JWS_ALG

        key_type = BLS12381G2

        assert key_type.key_type == BLS12381G2_KEY_NAME
        assert key_type.multicodec_name == BLS12381G2_MULTICODEC_NAME
        assert key_type.multicodec_prefix == BLS12381G2_PREFIX_BYTES
        assert key_type.jws_algorithm == BLS12381G2_JWS_ALG

        key_type = BLS12381G1G2

        assert key_type.key_type == BLS12381G1G2_KEY_NAME
        assert key_type.multicodec_name == BLS12381G1G2_MULTICODEC_NAME
        assert key_type.multicodec_prefix == BLS12381G1G2_PREFIX_BYTES
        assert key_type.jws_algorithm == BLS12381G1G2_JWS_ALG
