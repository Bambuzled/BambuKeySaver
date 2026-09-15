#!/usr/bin/env python3
"""Decode a Bambu get_app_cert response into PEM files. Based on https://github.com/danielwoz/BambuSlicerKeySaver/blob/5bf97a3fa3d3c83657bf1d8cfc14f7443cbf057d/win/appcert_cipher.h

Usage:
    curl '<cert-api-url>' > certs.json
    ./decrypt.py certs.json [-o outdir]

Writes:
    cert_0.pem ... cert_N.pem   each certificate from the "cert" field (0 = leaf)
    chain.pem                   all certificates concatenated, in response order
    crl.pem                     the "crl" entries
    key.pem                     the recovered RSA private key (PKCS#1)

The "key" field is base64 over::

    nonce(12) | 16 unknown bytes | ct_len(4, little-endian) | ciphertext

The ciphertext is AES-256-CTR under a *fixed* key (00 01 .. 1f) with the AES
S-box replaced by a fixed non-standard permutation; the substitution is used in
both SubBytes and the key schedule's SubWord.  Keystream block i is
E(KEY, nonce || BE32(2 + i)) -- the first data block uses counter 2.  Nothing in
the request contributes to the key. 

The plaintext is a "SKEY" struct::

    magic "SKEY" | version | six size words        (32 bytes)
    p | q | dp | dq | qinv                         (128 bytes each, big-endian)

No third-party modules are required.
"""

import argparse
import base64
import binascii
import json
import math
import re
import sys
from pathlib import Path

# --- cipher ----------------------------------------------------------------

SBOX = bytes.fromhex(
    "c5574d6c3a9505e0a3ba361fea51533b0e074e64500440e8626e9f2d708b2849"
    "d5f9658d74687c6f0a6ab3af38fe7e8a477fb01600d40f13c9804aac8c4fa798"
    "83945d48b4e93019039925bf8e41a0e4c3cf2cabd2321a0c11b5566315a6690b"
    "88bb4c10cb75fa81f8cda1d697b726c69ef15fe5a987c7dc8f7a86209ad108c2"
    "8409331bdd1efd0171da770dd7de93caa5d0e6608937c821597996ad2434b944"
    "fcc1aef382464331e32e4bfb9255ed45766daa3ff55a91782206ffd9357d7bdb"
    "54129cd8d3ee1742523ea4e7df9df2f4ef73f65eb15b18e29b58a82ae13d90b6"
    "1cbd61eb23a26739f0bcb2f7852772cc29b81dbe66c42fce143c6bec5c2bc002"
)

RCON = bytes([0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80,
              0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d])

APPCERT_KEY = bytes(range(32))  # 00 01 02 .. 1f


def _xtime(a):
    return ((a << 1) ^ (0x1b if a & 0x80 else 0)) & 0xFF


def _gmul(a, b):
    r = 0
    while b:
        if b & 1:
            r ^= a
        a = _xtime(a)
        b >>= 1
    return r & 0xFF


def _key_expand(key):
    """AES-256 key schedule (Nk=8, Nr=14) using SBOX for SubWord."""
    w = [list(key[4 * i:4 * i + 4]) for i in range(8)]
    for i in range(8, 60):
        t = list(w[i - 1])
        if i % 8 == 0:
            t = [SBOX[t[1]] ^ RCON[i // 8 - 1], SBOX[t[2]], SBOX[t[3]], SBOX[t[0]]]
        elif i % 8 == 4:
            t = [SBOX[x] for x in t]
        w.append([w[i - 8][j] ^ t[j] for j in range(4)])
    return [bytes(b for c in range(4) for b in w[4 * r + c]) for r in range(15)]


def _encrypt_block(block, rk):
    """One AES-256 block encryption; column-major state (s[4*col + row])."""
    s = [block[i] ^ rk[0][i] for i in range(16)]
    for rnd in range(1, 15):
        s = [SBOX[b] for b in s]
        s = [s[4 * ((c + r) % 4) + r] for c in range(4) for r in range(4)]
        if rnd < 14:
            t = []
            for c in range(4):
                a0, a1, a2, a3 = s[4 * c:4 * c + 4]
                t += [_gmul(a0, 2) ^ _gmul(a1, 3) ^ a2 ^ a3,
                      a0 ^ _gmul(a1, 2) ^ _gmul(a2, 3) ^ a3,
                      a0 ^ a1 ^ _gmul(a2, 2) ^ _gmul(a3, 3),
                      _gmul(a0, 3) ^ a1 ^ a2 ^ _gmul(a3, 2)]
            s = t
        s = [s[i] ^ rk[rnd][i] for i in range(16)]
    return bytes(s)


def ctr_xor(key, nonce, data):
    """CTR keystream XOR; block i uses counter 2 + i.  Decrypt == encrypt."""
    rk = _key_expand(key)
    out = bytearray(len(data))
    for i in range((len(data) + 15) // 16):
        ks = _encrypt_block(nonce + (2 + i).to_bytes(4, "big"), rk)
        chunk = data[i * 16:i * 16 + 16]
        out[i * 16:i * 16 + len(chunk)] = bytes(x ^ y for x, y in zip(chunk, ks))
    return bytes(out)


# --- key blob --------------------------------------------------------------

SKEY_MAGIC = b"SKEY"[::-1]  # stored little-endian: 59 45 4b 53


def b64decode_any(text):
    """Decode base64 accepting both the standard and URL-safe alphabets."""
    s = re.sub(r"\s+", "", text).replace("-", "+").replace("_", "/")
    return base64.b64decode(s + "=" * (-len(s) % 4))


def decode_key_blob(key_b64):
    """Return the CRT components from a get_app_cert "key" field."""
    blob = b64decode_any(key_b64)
    if len(blob) < 32:
        raise ValueError(f"key blob too short ({len(blob)} bytes)")
    nonce = blob[:12]
    ct_len = int.from_bytes(blob[28:32], "little")
    if 32 + ct_len > len(blob):
        ct_len = len(blob) - 32
    pt = ctr_xor(APPCERT_KEY, nonce, blob[32:32 + ct_len])

    if pt[:4] != SKEY_MAGIC:
        raise ValueError("SKEY magic missing -- not a key blob, or the format changed "
                         f"(got {pt[:4].hex()}, want {SKEY_MAGIC.hex()})")

    # Header: magic | version | bits | len(p) | len(q) | len(dp) | len(dq) | len(qinv)
    words = [int.from_bytes(pt[4 * i:4 * i + 4], "little") for i in range(8)]
    version, bits, sizes = words[1], words[2], words[3:8]
    if any(sz <= 0 for sz in sizes) or 32 + sum(sizes) > len(pt):
        raise ValueError(f"implausible component sizes in the SKEY header: {sizes}")

    vals, off = [], 32
    for sz in sizes:
        vals.append(int.from_bytes(pt[off:off + sz], "big"))
        off += sz
    p, q, dp, dq, qinv = vals
    return {"nonce": nonce, "version": version, "bits": bits,
            "p": p, "q": q, "dp": dp, "dq": dq, "qinv": qinv}


def rsa_from_crt(p, q, dp, dq, qinv):
    """Rebuild the full RSA key.  e is recovered from dp, not assumed."""
    n = p * q
    bad = ("CRT components are not self-consistent -- the blob decoded but does "
           "not hold a valid RSA key")
    try:
        e = pow(dp, -1, p - 1)
        e2 = pow(dq, -1, q - 1)
        lam = (p - 1) * (q - 1) // math.gcd(p - 1, q - 1)
        d = pow(e, -1, lam)
    except ValueError as exc:
        raise ValueError(f"{bad} ({exc})") from exc
    if e != e2:
        raise ValueError(f"{bad} (dp and dq disagree on the public exponent)")
    if (qinv * q) % p != 1:
        raise ValueError(f"{bad} (qinv is not the inverse of q mod p)")
    if d % (p - 1) != dp % (p - 1) or d % (q - 1) != dq % (q - 1):
        raise ValueError(f"{bad} (dp/dq do not agree with the private exponent)")
    return n, e, d


# --- minimal DER -----------------------------------------------------------

def _der_read(buf, off):
    """Read one TLV.  Returns (tag, content, next_offset)."""
    tag = buf[off]
    off += 1
    ln = buf[off]
    off += 1
    if ln & 0x80:
        k = ln & 0x7F
        ln = int.from_bytes(buf[off:off + k], "big")
        off += k
    return tag, buf[off:off + ln], off + ln


def _der_children(content):
    out, off = [], 0
    while off < len(content):
        tag, body, off = _der_read(content, off)
        out.append((tag, body))
    return out


def _der_len(n):
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def _der_int(v):
    b = v.to_bytes((v.bit_length() + 8) // 8, "big") or b"\x00"
    return b"\x02" + _der_len(len(b)) + b


def _der_seq(payload):
    return b"\x30" + _der_len(len(payload)) + payload


def _tbs(der):
    _, cert_body, _ = _der_read(der, 0)
    _, tbs, _ = _der_read(cert_body, 0)
    return tbs


def cert_modulus(der):
    """Pull the RSA modulus out of a DER certificate, or None."""
    try:
        for tag, body in _der_children(_tbs(der)):
            if tag != 0x30:
                continue
            kids = _der_children(body)
            if len(kids) == 2 and kids[0][0] == 0x30 and kids[1][0] == 0x03:
                spk = kids[1][1][1:]  # drop the unused-bits count
                _, rsapub, _ = _der_read(spk, 0)   # RSAPublicKey ::= SEQ { n, e }
                _, n_body = _der_children(rsapub)[0]
                return int.from_bytes(n_body, "big")
    except (IndexError, ValueError):
        pass
    return None


def cert_common_name(der):
    """Best-effort subject CN, for the summary line only."""
    try:
        seqs = [b for t, b in _der_children(_tbs(der)) if t == 0x30]
        # issuer and subject are RDNSequences; the subject is the later of the two
        # that parse as SET-of-SEQUENCE-of(OID, string).
        found = []
        for body in seqs:
            for t, rdn in _der_children(body):
                if t != 0x31:
                    continue
                for t2, av in _der_children(rdn):
                    kids = _der_children(av)
                    if len(kids) == 2 and kids[0][0] == 0x06 and kids[0][1] == b"\x55\x04\x03":
                        found.append(kids[1][1].decode("utf-8", "replace"))
        return found[-1] if found else None
    except (IndexError, ValueError, UnicodeDecodeError):
        return None


# --- PEM -------------------------------------------------------------------

def pem_wrap(label, der):
    b = base64.b64encode(der).decode()
    lines = "\n".join(b[i:i + 64] for i in range(0, len(b), 64))
    return f"-----BEGIN {label}-----\n{lines}\n-----END {label}-----\n"


def split_pem(text, label):
    """Return [(pem_text, der_bytes)] for every block with this label."""
    pat = re.compile(r"-----BEGIN " + label + r"-----(.*?)-----END " + label + r"-----", re.S)
    out = []
    for m in pat.finditer(text):
        try:
            der = base64.b64decode(re.sub(r"\s+", "", m.group(1)))
        except binascii.Error:
            continue
        out.append((pem_wrap(label, der), der))
    return out


def private_key_pem(n, e, d, p, q, dp, dq, qinv):
    body = b"".join(_der_int(v) for v in (0, n, e, d, p, q, dp, dq, qinv))
    return pem_wrap("RSA PRIVATE KEY", _der_seq(body))


# --- driver ----------------------------------------------------------------

def load_json(path):
    return json.loads(Path(path).read_text(errors="replace"))


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Decode a Bambu get_app_cert JSON response into PEM files.")
    ap.add_argument("response", help="file containing the server's JSON response")
    ap.add_argument("-o", "--out-dir", default=".", help="output directory (default: .)")
    args = ap.parse_args(argv)

    try:
        doc = load_json(args.response)
    except (OSError, json.JSONDecodeError) as exc:
        sys.exit(f"error: cannot read JSON from {args.response}: {exc}")

    if doc.get("code") not in (0, None) or doc.get("error"):
        sys.exit(f"error: server returned code={doc.get('code')} "
                 f"message={doc.get('message')!r} error={doc.get('error')!r}")

    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    written = []

    certs = split_pem(doc.get("cert") or "", "CERTIFICATE")
    if not certs:
        print("warning: no certificates in the response", file=sys.stderr)
    for i, (pem, der) in enumerate(certs):
        path = out / f"cert_{i}.pem"
        path.write_text(pem)
        cn = cert_common_name(der)
        written.append((path, f"CN={cn}" if cn else "certificate"))

    if certs:
        path = out / "chain.pem"
        path.write_text("".join(pem for pem, _ in certs))
        written.append((path, f"{len(certs)} certificates, response order"))

    crl_field = doc.get("crl") or []
    if isinstance(crl_field, str):
        crl_field = [crl_field]
    crls = [b for entry in crl_field for b in split_pem(entry, "X509 CRL")]
    if crls:
        path = out / "crl.pem"
        path.write_text("".join(pem for pem, _ in crls))
        written.append((path, f"{len(crls)} CRL{'s' if len(crls) != 1 else ''}"))

    if doc.get("key"):
        try:
            k = decode_key_blob(doc["key"])
            n, e, d = rsa_from_crt(k["p"], k["q"], k["dp"], k["dq"], k["qinv"])
        except ValueError as exc:
            sys.exit(f"error: could not decode the key blob: {exc}")
        leaf_n = cert_modulus(certs[0][1]) if certs else None
        if leaf_n is not None and leaf_n != n:
            sys.exit("error: recovered modulus does NOT match cert_0.pem -- "
                     "the key does not belong to this certificate (nothing written)")

        path = out / "key.pem"
        path.write_text(private_key_pem(n, e, d, k["p"], k["q"],
                                        k["dp"], k["dq"], k["qinv"]))
        path.chmod(0o600)
        written.append((path, f"RSA private key, {n.bit_length()} bits, e={e}"))
        if leaf_n is None:
            print("note: could not read the leaf certificate modulus; key not cross-checked",
                  file=sys.stderr)
        else:
            written.append((None, "verified: recovered modulus matches cert_0.pem"))
    else:
        print("warning: no \"key\" field in the response", file=sys.stderr)

    for path, note in written:
        if path is None:
            print(f"  {note}")
        else:
            print(f"  {path}  ({note})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
