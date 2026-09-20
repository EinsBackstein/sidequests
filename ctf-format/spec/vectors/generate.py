#!/usr/bin/env python3
"""Generate the committed cross-implementation vectors for spec/SPEC.md §19/§20.

Run from anywhere:

    python3 spec/vectors/generate.py

The script writes two artifacts *together*, so they cannot drift:

    spec/vectors/primitives.json                       (human-readable, hex)
    crates/ctf-format/tests/vectors/vectors_data.rs    (plain Rust, byte arrays)

Every vector's expected value comes from an implementation that is independent
of the Rust code under test. The second implementation per role:

    role        second implementation
    ---------   ------------------------------------------------------------
    hash        pure-Python BLAKE3 in this file (compression function, 1024-
                byte chunks, the binary tree, PARENT/ROOT/CHUNK_START/CHUNK_END).
                Validated below against the two published digests for "" and
                "abc" before any vector is emitted.
    kdf         pure-Python HKDF-SHA-256 over hmac/hashlib (RFC 5869), also
                validated against the three RFC 5869 SHA-256 test cases.
    aead(1)     `cryptography` AESGCM (OpenSSL-backed) — independent of AWS-LC.
    aead(2)     pure-Python HChaCha20 (validated against the draft-irtf-cfrg-
                xchacha HChaCha20 vector and its A.3 AEAD vector) feeding
                `cryptography` ChaCha20Poly1305 for the inner IETF construction.
    signature   Ed25519 from `cryptography` (OpenSSL); ML-DSA-65 from the
                `openssl` 3.6.4 CLI. Both sign the identical transcript.
    kem         ML-KEM-768 keypair/encapsulation from the `openssl` 3.6.4 CLI;
                X25519 from `cryptography`; the §20.1 HKDF combiner
                reimplemented here over hmac/hashlib with the LP encoding.

The CLI `openssl` must be on PATH; no Python package beyond `cryptography`
(46.0.7 here) and the standard library is used. ML-KEM-768 and ML-DSA-65 draw
fresh randomness in OpenSSL, so those fields change on each run — the two
committed artifacts are always rewritten together, which is what keeps them in
sync. Everything else is deterministic.

Reverse direction (crate → openssl), recorded here because the hermetic test
cannot run openssl: with the committed seeds, the Rust crate produced a hybrid
signature over the committed transcript. The Ed25519 half is required by the
test to reproduce the committed signature exactly (Ed25519 is deterministic).
The ML-DSA-65 half was verified by

    openssl pkeyutl -verify -pubin -inkey committed_pub.pem -rawin \
        -in transcript -sigfile crate_pq_sig

and reported "Signature Verified Successfully" (openssl 3.6.4), where
committed_pub.pem is the committed 1952-byte verifying key in an SPKI wrapper.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import struct
import subprocess
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

ROOT = Path(__file__).resolve().parent.parent.parent
JSON_PATH = ROOT / "spec" / "vectors" / "primitives.json"
RUST_PATH = ROOT / "crates" / "ctf-format" / "tests" / "vectors" / "vectors_data.rs"


# ---------------------------------------------------------------------------
# BLAKE3 (pure Python) — the independent implementation for the `hash` role.
# ---------------------------------------------------------------------------

_IV = [
    0x6A09E667,
    0xBB67AE85,
    0x3C6EF372,
    0xA54FF53A,
    0x510E527F,
    0x9B05688C,
    0x1F83D9AB,
    0x5BE0CD19,
]
_MSG_PERMUTATION = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8]
_CHUNK_START = 1
_CHUNK_END = 2
_PARENT = 4
_ROOT = 8
_BLOCK_LEN = 64
_CHUNK_LEN = 1024
_M32 = 0xFFFFFFFF


def _rotr(x: int, n: int) -> int:
    return ((x >> n) | (x << (32 - n))) & _M32


def _compress(cv, block, counter, block_len, flags):
    st = [
        cv[0], cv[1], cv[2], cv[3], cv[4], cv[5], cv[6], cv[7],
        _IV[0], _IV[1], _IV[2], _IV[3],
        counter & _M32, (counter >> 32) & _M32, block_len, flags,
    ]
    m = list(block)

    def g(a, b, c, d, x, y):
        st[a] = (st[a] + st[b] + x) & _M32
        st[d] = _rotr(st[d] ^ st[a], 16)
        st[c] = (st[c] + st[d]) & _M32
        st[b] = _rotr(st[b] ^ st[c], 12)
        st[a] = (st[a] + st[b] + y) & _M32
        st[d] = _rotr(st[d] ^ st[a], 8)
        st[c] = (st[c] + st[d]) & _M32
        st[b] = _rotr(st[b] ^ st[c], 7)

    def rnd(words):
        g(0, 4, 8, 12, words[0], words[1])
        g(1, 5, 9, 13, words[2], words[3])
        g(2, 6, 10, 14, words[4], words[5])
        g(3, 7, 11, 15, words[6], words[7])
        g(0, 5, 10, 15, words[8], words[9])
        g(1, 6, 11, 12, words[10], words[11])
        g(2, 7, 8, 13, words[12], words[13])
        g(3, 4, 9, 14, words[14], words[15])

    for i in range(7):
        rnd(m)
        if i < 6:
            m = [m[p] for p in _MSG_PERMUTATION]
    return [st[i] ^ st[i + 8] for i in range(8)] + [
        st[i + 8] ^ cv[i] for i in range(8)
    ]


def _block_words(block: bytes):
    padded = block + b"\x00" * (_BLOCK_LEN - len(block))
    return list(struct.unpack("<16I", padded))


def _blocks(data: bytes):
    if not data:
        return [b""]
    return [data[i : i + _BLOCK_LEN] for i in range(0, len(data), _BLOCK_LEN)]


def _chunk_cv(chunk: bytes, counter: int, flags: int = 0):
    cv = list(_IV)
    blocks = _blocks(chunk)
    for i, blk in enumerate(blocks):
        f = flags
        if i == 0:
            f |= _CHUNK_START
        if i == len(blocks) - 1:
            f |= _CHUNK_END
        cv = _compress(cv, _block_words(blk), counter, len(blk), f)[:8]
    return cv


def _chunk_root(chunk: bytes, counter: int, flags: int = 0) -> bytes:
    cv = list(_IV)
    blocks = _blocks(chunk)
    out = None
    for i, blk in enumerate(blocks):
        f = flags
        if i == 0:
            f |= _CHUNK_START
        if i == len(blocks) - 1:
            f |= _CHUNK_END | _ROOT
        out = _compress(cv, _block_words(blk), counter, len(blk), f)
        cv = out[:8]
    return struct.pack("<16I", *out)[:32]


def _parent_cv(left, right, flags: int = 0):
    return _compress(list(_IV), list(left) + list(right), 0, 64, _PARENT | flags)[:8]


def _parent_root(left, right, flags: int = 0) -> bytes:
    out = _compress(
        list(_IV), list(left) + list(right), 0, 64, _PARENT | _ROOT | flags
    )
    return struct.pack("<16I", *out)[:32]


def _largest_power_of_two_below(n: int) -> int:
    p = 1
    while p * 2 < n:
        p *= 2
    return p


def _subtree_cv(data: bytes, counter: int):
    chunks = (len(data) + _CHUNK_LEN - 1) // _CHUNK_LEN
    if chunks <= 1:
        return _chunk_cv(data, counter)
    p = _largest_power_of_two_below(chunks)
    return _parent_cv(
        _subtree_cv(data[: p * _CHUNK_LEN], counter),
        _subtree_cv(data[p * _CHUNK_LEN :], counter + p),
    )


def blake3(data: bytes) -> bytes:
    chunks = (len(data) + _CHUNK_LEN - 1) // _CHUNK_LEN
    if chunks <= 1:
        return _chunk_root(data, 0)
    p = _largest_power_of_two_below(chunks)
    return _parent_root(
        _subtree_cv(data[: p * _CHUNK_LEN], 0),
        _subtree_cv(data[p * _CHUNK_LEN :], p),
    )


def _validate_blake3() -> None:
    known = [
        (b"", "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"),
        (b"abc", "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85"),
    ]
    for data, expected in known:
        got = blake3(data).hex()
        if got != expected:
            raise SystemExit(f"BLAKE3 self-test failed for {data!r}: {got} != {expected}")


# ---------------------------------------------------------------------------
# HKDF-SHA-256 (pure Python, RFC 5869)
# ---------------------------------------------------------------------------


def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    if not salt:
        salt = b"\x00" * hashlib.sha256().digest_size
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    okm = b""
    t = b""
    counter = 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        okm += t
        counter += 1
    return okm[:length]


def _validate_hkdf() -> None:
    tc1_ikm = bytes([0x0B]) * 22
    tc1_salt = bytes(range(0x00, 0x0D))
    tc1_info = bytes(range(0xF0, 0xFA))
    tc1_okm = "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"

    tc2_ikm = bytes(range(0x00, 0x50))
    tc2_salt = bytes(range(0x60, 0xB0))
    tc2_info = bytes(range(0xB0, 0x100))
    tc2_okm = (
        "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c"
        "59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71"
        "cc30c58179ec3e87c14c01d5c1f3434f1d87"
    )

    tc3_ikm = bytes([0x0B]) * 22
    tc3_okm = "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"

    cases = [
        (tc1_ikm, tc1_salt, tc1_info, 42, tc1_okm),
        (tc2_ikm, tc2_salt, tc2_info, 82, tc2_okm),
        (tc3_ikm, b"", b"", 42, tc3_okm),
    ]
    for ikm, salt, info, length, expected in cases:
        got = hkdf_sha256(ikm, salt, info, length).hex()
        if got != expected:
            raise SystemExit(f"HKDF self-test failed: {got} != {expected}")


# ---------------------------------------------------------------------------
# HChaCha20 + XChaCha20-Poly1305 (pure HChaCha20; cryptography for the AEAD)
# ---------------------------------------------------------------------------


def _rotl(x: int, n: int) -> int:
    return ((x << n) | (x >> (32 - n))) & _M32


def _quarter_round(s, a, b, c, d):
    s[a] = (s[a] + s[b]) & _M32
    s[d] = _rotl(s[d] ^ s[a], 16)
    s[c] = (s[c] + s[d]) & _M32
    s[b] = _rotl(s[b] ^ s[c], 12)
    s[a] = (s[a] + s[b]) & _M32
    s[d] = _rotl(s[d] ^ s[a], 8)
    s[c] = (s[c] + s[d]) & _M32
    s[b] = _rotl(s[b] ^ s[c], 7)


def hchacha20(key: bytes, nonce16: bytes) -> bytes:
    state = (
        list(struct.unpack("<4I", b"expand 32-byte k"))
        + list(struct.unpack("<8I", key))
        + list(struct.unpack("<4I", nonce16))
    )
    for _ in range(10):
        _quarter_round(state, 0, 4, 8, 12)
        _quarter_round(state, 1, 5, 9, 13)
        _quarter_round(state, 2, 6, 10, 14)
        _quarter_round(state, 3, 7, 11, 15)
        _quarter_round(state, 0, 5, 10, 15)
        _quarter_round(state, 1, 6, 11, 12)
        _quarter_round(state, 2, 7, 8, 13)
        _quarter_round(state, 3, 4, 9, 14)
    return struct.pack("<8I", *(state[0:4] + state[12:16]))


def xchacha20poly1305_seal(
    key: bytes, nonce24: bytes, aad: bytes, plaintext: bytes
) -> bytes:
    subkey = hchacha20(key, nonce24[:16])
    nonce12 = b"\x00\x00\x00\x00" + nonce24[16:24]
    return ChaCha20Poly1305(subkey).encrypt(nonce12, plaintext, aad)


def _validate_hchacha20() -> None:
    key = bytes(range(32))
    nonce = bytes.fromhex("000000090000004a0000000031415927")
    expected = "82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc"
    if hchacha20(key, nonce).hex() != expected:
        raise SystemExit("HChaCha20 self-test failed")

    k = bytes.fromhex(
        "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"
    )
    n = bytes.fromhex("404142434445464748494a4b4c4d4e4f5051525354555657")
    aad = bytes.fromhex("50515253c0c1c2c3c4c5c6c7")
    pt = (
        b"Ladies and Gentlemen of the class of '99: If I could offer you only "
        b"one tip for the future, sunscreen would be it."
    )
    expected_ct = (
        "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb"
        "731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b452"
        "2f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff9"
        "21f9664c97637da9768812f615c68b13b52e"
        "c0875924c1c7987947deafd8780acf49"
    )
    if xchacha20poly1305_seal(k, n, aad, pt).hex() != expected_ct:
        raise SystemExit("XChaCha20-Poly1305 self-test failed")


# ---------------------------------------------------------------------------
# openssl helpers (ML-KEM-768 and ML-DSA-65)
# ---------------------------------------------------------------------------


def _openssl(*args: str) -> None:
    subprocess.run(["openssl", *args], check=True, capture_output=True)


def _openssl_out(*args: str) -> bytes:
    return subprocess.run(
        ["openssl", *args], check=True, capture_output=True
    ).stdout


def _parse_hex_block(text: str, label: str) -> bytes:
    match = re.search(rf"{label}:\n((?:\s+[0-9a-f:]+\n)+)", text)
    if match is None:
        raise SystemExit(f"openssl output did not contain a {label!r} block")
    return bytes.fromhex(re.sub(r"[^0-9a-f]", "", match.group(1)))


def openssl_mlkem768(tmp: Path):
    """Return (decapsulation seed d||z, encapsulation key ek, ciphertext, ss)."""
    key = tmp / "mlkem.pem"
    _openssl("genpkey", "-algorithm", "ML-KEM-768", "-out", str(key))
    text = _openssl_out("pkey", "-in", str(key), "-text", "-noout").decode()
    seed = _parse_hex_block(text, "seed")
    if len(seed) != 64:
        raise SystemExit(f"ML-KEM seed is {len(seed)} bytes, expected 64")
    spki = _openssl_out("pkey", "-in", str(key), "-pubout", "-outform", "DER")
    ek = spki[-1184:]
    if len(ek) != 1184:
        raise SystemExit("ML-KEM encapsulation key extraction failed")

    ct_path = tmp / "mlkem.ct"
    ss_path = tmp / "mlkem.ss"
    _openssl(
        "pkeyutl",
        "-encap",
        "-inkey",
        str(key),
        "-out",
        str(ct_path),
        "-secret",
        str(ss_path),
    )
    ct = ct_path.read_bytes()
    ss = ss_path.read_bytes()
    if len(ct) != 1088 or len(ss) != 32:
        raise SystemExit("ML-KEM encapsulation produced unexpected sizes")
    return seed, ek, ct, ss


def openssl_mldsa65(tmp: Path, message: bytes):
    """Return (signing seed, verifying key, signature) for `message`."""
    key = tmp / "mldsa.pem"
    msg = tmp / "mldsa.msg"
    sig = tmp / "mldsa.sig"
    msg.write_bytes(message)
    _openssl("genpkey", "-algorithm", "ML-DSA-65", "-out", str(key))
    text = _openssl_out("pkey", "-in", str(key), "-text", "-noout").decode()
    seed = _parse_hex_block(text, "seed")
    if len(seed) != 32:
        raise SystemExit(f"ML-DSA seed is {len(seed)} bytes, expected 32")
    spki = _openssl_out("pkey", "-in", str(key), "-pubout", "-outform", "DER")
    vk = spki[-1952:]
    if len(vk) != 1952:
        raise SystemExit("ML-DSA verifying key extraction failed")
    _openssl(
        "pkeyutl",
        "-sign",
        "-inkey",
        str(key),
        "-rawin",
        "-in",
        str(msg),
        "-out",
        str(sig),
    )
    signature = sig.read_bytes()
    if len(signature) != 3309:
        raise SystemExit("ML-DSA signature has unexpected size")
    return seed, vk, signature


# ---------------------------------------------------------------------------
# X25519 + the §20.1 combiner
# ---------------------------------------------------------------------------


def x25519_public(secret: bytes) -> bytes:
    return (
        X25519PrivateKey.from_private_bytes(secret)
        .public_key()
        .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    )


def x25519_agree(secret: bytes, peer_public: bytes) -> bytes:
    return X25519PrivateKey.from_private_bytes(secret).exchange(
        X25519PublicKey.from_public_bytes(peer_public)
    )


def lp(data: bytes) -> bytes:
    return len(data).to_bytes(4, "little") + data


def kem_content_key(
    ss_x25519: bytes,
    ss_mlkem: bytes,
    ct_x25519: bytes,
    ct_mlkem: bytes,
    pk_x25519: bytes,
    pk_mlkem: bytes,
    suite_id: int,
    version_major: int,
    label: bytes,
) -> bytes:
    ikm = ss_x25519 + ss_mlkem
    salt = (
        b"ctf/kem/v1"
        + suite_id.to_bytes(2, "little")
        + version_major.to_bytes(2, "little")
    )
    info = (
        lp(ct_x25519)
        + lp(ct_mlkem)
        + lp(pk_x25519)
        + lp(pk_mlkem)
        + lp(label)
    )
    return hkdf_sha256(ikm, salt, info, 32)


# ---------------------------------------------------------------------------
# Vector construction
# ---------------------------------------------------------------------------


def hash_vectors():
    vectors = []
    lengths = [0, 1, 3, 64, 1024, 1025, 4096]
    for n in lengths:
        data = bytes(i % 251 for i in range(n))
        name = f"blake3-len-{n}"
        vectors.append(
            {
                "role": "hash",
                "name": name,
                "suite": 1,
                "source": "pure-Python BLAKE3 (spec/vectors/generate.py)",
                "inputs": [data.hex()],
                "expected": blake3(data).hex(),
            }
        )
    vectors.append(
        {
            "role": "hash",
            "name": "blake3-abc",
            "suite": 2,
            "source": "pure-Python BLAKE3 (spec/vectors/generate.py)",
            "inputs": [b"abc".hex()],
            "expected": blake3(b"abc").hex(),
        }
    )
    return vectors


def kdf_vectors():
    tc1_ikm = bytes([0x0B]) * 22
    tc1_salt = bytes(range(0x00, 0x0D))
    tc1_info = bytes(range(0xF0, 0xFA))

    tc2_ikm = bytes(range(0x00, 0x50))
    tc2_salt = bytes(range(0x60, 0xB0))
    tc2_info = bytes(range(0xB0, 0x100))

    tc3_ikm = bytes([0x0B]) * 22

    shaped_ikm = bytes([0x11]) * 32 + bytes([0x22]) * 32
    shaped_salt = b"ctf/kem/v1" + (1).to_bytes(2, "little") + (0).to_bytes(2, "little")
    shaped_info = (
        lp(b"ct-x25519")
        + lp(b"ct-mlkem-768")
        + lp(b"pk-x25519")
        + lp(b"pk-mlkem-768")
        + lp(b"storage")
    )

    cases = [
        ("hkdf-sha256-rfc5869-tc1", tc1_ikm, tc1_salt, tc1_info, 42),
        ("hkdf-sha256-rfc5869-tc2", tc2_ikm, tc2_salt, tc2_info, 82),
        ("hkdf-sha256-rfc5869-tc3", tc3_ikm, b"", b"", 42),
        (
            "hkdf-sha256-crate-shaped",
            shaped_ikm,
            shaped_salt,
            shaped_info,
            32,
        ),
    ]
    vectors = []
    for name, ikm, salt, info, length in cases:
        vectors.append(
            {
                "role": "kdf",
                "name": name,
                "suite": 1,
                "source": "pure-Python HKDF-SHA-256 (spec/vectors/generate.py)",
                "inputs": [ikm.hex(), salt.hex(), info.hex()],
                "expected": hkdf_sha256(ikm, salt, info, length).hex(),
            }
        )
    return vectors


def aead_vectors():
    key = bytes(range(32))
    aad = b"ctf/vectors/v1"
    aes_nonce = bytes(range(12))
    aes_pt = b"the quick brown fox jumps over the lazy dog"
    xchacha_nonce = bytes(range(24))
    xchacha_pt = b"pack my box with five dozen liquor jugs"

    aes_ct = AESGCM(key).encrypt(aes_nonce, aes_pt, aad)
    aes_empty_ct = AESGCM(key).encrypt(aes_nonce, b"", aad)
    xchacha_ct = xchacha20poly1305_seal(key, xchacha_nonce, aad, xchacha_pt)

    return [
        {
            "role": "aead",
            "name": "aes-256-gcm-suite1",
            "suite": 1,
            "source": "Python cryptography AESGCM (OpenSSL)",
            "inputs": [key.hex(), aes_nonce.hex(), aad.hex(), aes_pt.hex()],
            "expected": aes_ct.hex(),
        },
        {
            "role": "aead",
            "name": "aes-256-gcm-suite1-empty",
            "suite": 1,
            "source": "Python cryptography AESGCM (OpenSSL)",
            "inputs": [key.hex(), aes_nonce.hex(), aad.hex(), b"".hex()],
            "expected": aes_empty_ct.hex(),
        },
        {
            "role": "aead",
            "name": "xchacha20-poly1305-suite2",
            "suite": 2,
            "source": "Python HChaCha20 + cryptography ChaCha20Poly1305 (OpenSSL)",
            "inputs": [
                key.hex(),
                xchacha_nonce.hex(),
                aad.hex(),
                xchacha_pt.hex(),
            ],
            "expected": xchacha_ct.hex(),
        },
    ]


def signature_vectors(tmp: Path):
    transcript = b"ctf/vectors/v1 signature transcript"
    ed_seed = bytes(range(32))
    ed_key = Ed25519PrivateKey.from_private_bytes(ed_seed)
    ed_pk = ed_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    ed_sig = ed_key.sign(transcript)

    mldsa_seed, mldsa_pk, mldsa_sig = openssl_mldsa65(tmp, transcript)

    return [
        {
            "role": "signature",
            "name": "ed25519-ml-dsa-65-suite1",
            "suite": 1,
            "source": "cryptography Ed25519 + openssl ML-DSA-65",
            "inputs": [
                ed_pk.hex(),
                mldsa_pk.hex(),
                transcript.hex(),
                ed_sig.hex(),
                mldsa_sig.hex(),
                ed_seed.hex(),
                mldsa_seed.hex(),
            ],
            "expected": b"".hex(),
            "reverse_check": (
                "crate-produced signature verified by openssl 3.6.4; the Ed25519 "
                "half is reproduced exactly by the hermetic test"
            ),
        }
    ]


def kem_vectors(tmp: Path):
    sk_x25519 = bytes([0x5A]) * 32
    pk_x25519 = x25519_public(sk_x25519)
    eph_seed = bytes([0xA7]) * 32
    ct_x25519 = x25519_public(eph_seed)
    ss_x25519 = x25519_agree(eph_seed, pk_x25519)

    seed, ek, ct_mlkem, ss_mlkem = openssl_mlkem768(tmp)

    label = b"storage"
    expected = kem_content_key(
        ss_x25519,
        ss_mlkem,
        ct_x25519,
        ct_mlkem,
        pk_x25519,
        ek,
        1,
        0,
        label,
    )

    secret_key = sk_x25519 + seed
    ciphertext = ct_x25519 + ct_mlkem
    assert len(secret_key) == 96, len(secret_key)
    assert len(ciphertext) == 1120, len(ciphertext)

    return [
        {
            "role": "kem",
            "name": "x25519-ml-kem-768-suite1-storage",
            "suite": 1,
            "source": (
                "openssl ML-KEM-768 + cryptography X25519 + pure-Python "
                "§20.1 HKDF combiner"
            ),
            "inputs": [secret_key.hex(), ciphertext.hex(), label.hex()],
            "expected": expected.hex(),
        }
    ]


# ---------------------------------------------------------------------------
# Emitters
# ---------------------------------------------------------------------------


def _rust_bytes(data: bytes) -> str:
    if not data:
        return "&[]"
    body = ", ".join(f"0x{b:02x}" for b in data)
    return f"&[{body}]"


def render_rust(vectors) -> str:
    lines = [
        "// @generated by spec/vectors/generate.py — do not edit by hand.",
        "//",
        "// Cross-implementation vectors for the suite registry (spec §19/§20).",
        "// Each `expected` was derived from an independent implementation; see",
        "// spec/vectors/generate.py for the per-role provenance. This file and",
        "// spec/vectors/primitives.json are written by the same run.",
        "",
        "pub struct Vector {",
        '    pub role: &\'static str,',
        '    pub name: &\'static str,',
        "    pub suite: u16,",
        "    pub inputs: &'static [&'static [u8]],",
        "    pub expected: &'static [u8],",
        "}",
        "",
        "pub static VECTORS: &[Vector] = &[",
    ]
    for v in vectors:
        lines.append("    Vector {")
        lines.append(f'        role: "{v["role"]}",')
        lines.append(f'        name: "{v["name"]}",')
        lines.append(f'        suite: {v["suite"]},')
        inputs = ", ".join(_rust_bytes(bytes.fromhex(x)) for x in v["inputs"])
        lines.append(f"        inputs: &[{inputs}],")
        lines.append(f'        expected: {_rust_bytes(bytes.fromhex(v["expected"]))},')
        lines.append("    },")
    lines.append("];")
    lines.append("")
    return "\n".join(lines)


def main() -> None:
    _validate_blake3()
    _validate_hkdf()
    _validate_hchacha20()

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        vectors = []
        vectors += hash_vectors()
        vectors += kdf_vectors()
        vectors += aead_vectors()
        vectors += signature_vectors(tmp)
        vectors += kem_vectors(tmp)

    document = {
        "comment": (
            "Cross-implementation test vectors for the .ctf crypto suite "
            "registry (spec/SPEC.md §19/§20). Generated by "
            "spec/vectors/generate.py; each `source` names the independent "
            "implementation that produced `expected`. Byte strings are hex."
        ),
        "generated_by": "spec/vectors/generate.py",
        "vectors": vectors,
    }

    JSON_PATH.parent.mkdir(parents=True, exist_ok=True)
    RUST_PATH.parent.mkdir(parents=True, exist_ok=True)
    JSON_PATH.write_text(json.dumps(document, indent=2, ensure_ascii=False) + "\n")
    RUST_PATH.write_text(render_rust(vectors))

    # Keep the committed Rust identical to what `cargo fmt` would leave behind,
    # so a regeneration alone never shows a formatting diff.
    try:
        subprocess.run(
            ["rustfmt", "--edition", "2024", str(RUST_PATH)],
            check=True,
            capture_output=True,
        )
    except (OSError, subprocess.CalledProcessError):
        pass

    roles = {}
    for v in vectors:
        roles[v["role"]] = roles.get(v["role"], 0) + 1
    print(f"wrote {JSON_PATH.relative_to(ROOT)}")
    print(f"wrote {RUST_PATH.relative_to(ROOT)}")
    print("vectors per role:", roles)


if __name__ == "__main__":
    main()
