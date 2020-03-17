#!/usr/bin/python3

import time
import sys
import re
import base64
from ecc import getcurvebyname, ECPrivateKey, ECPublicKey, Random, Tools
from StopWatch import StopWatch

def nice_test_out(x, y = True):
	if x == y:
		return "✓"
	return "✕"

cv = getcurvebyname("curve25519")
ed = getcurvebyname("ed25519")

if len(sys.argv) < 2:
	print("Put a hex-encoded private key (scalar) as the first argument to this test to work with a predefined key for Curve25519.")
	print("Using random key instead.")
	print()

print("Starting from Curve25519 key")
print("============================")

# Create Curve25519 key
if len(sys.argv) >= 2:
	cvkeypair = ECPrivateKey(Tools.bytestoint_le(bytes.fromhex(sys.argv[1])), cv)
else:
	cvkeypair = ECPrivateKey.generate(cv)
cvpub = cvkeypair.pubkey
print("Secret scalar a:                ", cvkeypair.scalar)
print("Curve25519 public point A:      ", cvpub.point)

# Derive key on Ed25519 curve
edkeypair = ECPrivateKey(cvkeypair.scalar, ed)
print("Ed25519 public point A:         ", edkeypair.pubkey.point)

print()

edpubenc = edkeypair.pubkey.eddsa_encode()
print("OMEMO identity key (Ed25519):   ", base64.encodebytes(edpubenc).decode("utf-8").strip())

# Ensure Ed25519 pubkey derived from Ed25519 private key is same as derived from Curve25519 public key
edpub = ECPublicKey(cvpub.point.convert(ed))
assert(edkeypair.pubkey.point == edpub.point)

# Ensure Curve25519 pubkey derived from Ed25519 pubkey is same as derived from Curve25519 private key
cvpub = ECPublicKey(edpub.point.convert(cv))
assert(cvkeypair.pubkey.point == cvpub.point)

# Ensure decoded Ed25519 pubkey is same as derived
edpubdec = ECPublicKey.eddsa_decode(ed, edpubenc)
assert(edpubdec.point == edpub.point)

print("OMEMO fingerprint (Curve25519): ", re.sub(r".{8}", "\g<0> ", Tools.inttobytes_le(int(cvpub.point.x), 32).hex()))

msg = b"Foobar!"

signature = edkeypair.seddsa_sign(msg, Random.secure_rand(32))
print("OMEMO Signature (via SEd25519): ", signature)

print()

print("Verify correct message:         ", nice_test_out(edpub.eddsa_verify(msg, signature)))
print("Verify forged message:          ", nice_test_out(edpub.eddsa_verify(msg + b"x", signature), False))

print()

print("Starting from Ed25519 key")
print("=========================")

# Create Ed25519 key
edkeypair = ECPrivateKey.eddsa_generate(ed)
edpub = edkeypair.pubkey
print("Ed25519 seed (generated):       ", edkeypair.seed)
print("Secret scalar a:                ", edkeypair.scalar)
print("Ed25519 public point A:         ", edpub.point)

# Derive key on Curve25519 curve
cvkeypair = ECPrivateKey(edkeypair.scalar, cv)
print("Curve25519 public point A:      ", cvkeypair.pubkey.point)

print()

edpubenc = edkeypair.pubkey.eddsa_encode()
print("OMEMO identity key (Ed25519):   ", base64.encodebytes(edpubenc).decode("utf-8").strip())

# Ensure Curve25519 pubkey derived from Ed25519 pubkey is same as derived from Curve25519 private key
cvpub = ECPublicKey(edpub.point.convert(cv))
assert(cvkeypair.pubkey.point == cvpub.point)

# Ensure Ed25519 pubkey derived from Ed25519 private key is same as derived from Curve25519 public key
edpub = ECPublicKey(cvpub.point.convert(ed))
assert(edkeypair.pubkey.point == edpub.point)

# Ensure decoded Ed25519 pubkey is same as derived
edpubdec = ECPublicKey.eddsa_decode(ed, edpubenc)
assert(edpubdec.point == edpub.point)

print("OMEMO fingerprint (Curve25519): ", re.sub(r".{8}", "\g<0> ", Tools.inttobytes_le(int(cvpub.point.x), 32).hex()))

msg = b"Foobar!"

signature = edkeypair.eddsa_sign(msg)
print("OMEMO Signature (via Ed25519):  ", signature)

print()

print("Verify correct message:         ", nice_test_out(edpub.eddsa_verify(msg, signature)))
print("Verify forged message:          ", nice_test_out(edpub.eddsa_verify(msg + b"x", signature), False))
