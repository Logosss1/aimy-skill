"""Tests for tools.jwt_common (canonical JWT base64url + parse)."""
import base64
import json

from tools.jwt_common import (
    b64url_decode,
    b64url_encode,
    decode_jwt_header,
    decode_jwt_payload,
    parse_jwt,
)


def _make_token(header: dict, payload: dict) -> str:
    """Build a real-looking JWT (no signature, just structure)."""
    h = b64url_encode(json.dumps(header).encode())
    p = b64url_encode(json.dumps(payload).encode())
    return "%s.%s.sig" % (h, p)


class TestB64UrlEncode:
    def test_encode_decode_roundtrip(self):
        data = b"hello world"
        encoded = b64url_encode(data)
        assert "=" not in encoded
        assert b64url_decode(encoded) == data

    def test_no_padding(self):
        encoded = b64url_encode(b"a")
        assert "=" not in encoded
        # standard base64 would be "YQ==", urlsafe would be "YQ" after rstrip
        assert encoded == "YQ"

    def test_urlsafe_chars(self):
        # Data that produces + and / in standard b64 should use - and _ in urlsafe
        data = bytes([255, 255, 255, 255])
        encoded = b64url_encode(data)
        assert "+" not in encoded
        assert "/" not in encoded


class TestB64UrlDecode:
    def test_decode_with_padding_added(self):
        # Standard "YQ==" should decode from "YQ"
        assert b64url_decode("YQ") == b"a"

    def test_decode_empty(self):
        assert b64url_decode("") == b""


class TestParseJwt:
    def test_valid_token(self):
        token = _make_token({"alg": "HS256"}, {"sub": "123", "role": "admin"})
        header, payload, sig = parse_jwt(token)
        assert header == {"alg": "HS256"}
        assert payload == {"sub": "123", "role": "admin"}
        assert sig == "sig"

    def test_invalid_format(self):
        header, payload, sig = parse_jwt("not.a.valid.token.format")
        assert header is None
        assert payload is None
        assert sig is None

    def test_two_parts(self):
        header, payload, sig = parse_jwt("a.b")
        assert header is None

    def test_garbage_payload(self):
        token = "valid.garbage!!.sig"
        header, payload, sig = parse_jwt(token)
        assert header is None


class TestDecodeJwtHeaderPayload:
    def test_decode_payload(self):
        token = _make_token({"alg": "none"}, {"sub": "user"})
        assert decode_jwt_payload(token) == {"sub": "user"}

    def test_decode_header(self):
        token = _make_token({"alg": "HS256", "typ": "JWT"}, {"sub": "user"})
        assert decode_jwt_header(token) == {"alg": "HS256", "typ": "JWT"}

    def test_decode_invalid(self):
        assert decode_jwt_payload("invalid") is None
        assert decode_jwt_header("invalid") is None


class TestInteropWithStdlib:
    """Sanity: 与 Python 标准库结果等价."""

    def test_encode_matches_urlsafe_b64encode(self):
        data = b"some random data"
        stdlib = base64.urlsafe_b64encode(data).rstrip(b"=").decode()
        assert b64url_encode(data) == stdlib

    def test_decode_handles_full_padding(self):
        # Standard urlsafe with padding
        data = b"test"
        encoded = base64.urlsafe_b64encode(data).decode()
        assert b64url_decode(encoded.rstrip("=")) == data
