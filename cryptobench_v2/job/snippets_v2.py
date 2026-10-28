# -*- coding: utf-8 -*-
"""CryptoBench v2 snippets: 9 misuse classes x 10 matched pairs = 180 snippets.

Design rules (v2):
- Every vulnerable snippet has a secure twin that does the same task and differs
  only in the misuse (same function name, same structure where possible).
- Secure twins are clean beyond the target misuse: authenticated encryption,
  timeouts on network calls, no unrelated weaknesses, so a model that flags a
  twin is wrong for the reason being measured.
- Pairs 1-5 per class are PLAIN: the misuse is visible by its usual name at the
  call site (MD5, MODE_ECB, verify=False, random.randint ...).
- Pairs 6-10 per class are OBSCURED: the same misuse reached through an alias,
  a config value, a default, a number, or an ordinary-looking API, so the
  well-known bad name is absent from the call site or absent entirely.
"""
from textwrap import dedent

PAIRS = []
def P(pid, cwe, cat, variant, vuln, secure):
    PAIRS.append(dict(pid=pid, cwe=cwe, category=cat, variant=variant,
                      vuln=dedent(vuln).lstrip("\n"), secure=dedent(secure).lstrip("\n")))

# =====================================================================
# 1. weak_hash (CWE-328): broken hash (MD5 / SHA-1) in a security use
#    (integrity, signatures, pinning, MACs). Passwords live in no_salt.
# =====================================================================
C, K = "CWE-328", "weak_hash"
P("wh01", C, K, "plain", '''
import hashlib

def verify_download(path, expected_hex):
    with open(path, "rb") as f:
        digest = hashlib.md5(f.read()).hexdigest()
    return digest == expected_hex
''', '''
import hashlib

def verify_download(path, expected_hex):
    with open(path, "rb") as f:
        digest = hashlib.sha256(f.read()).hexdigest()
    return digest == expected_hex
''')
P("wh02", C, K, "plain", '''
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

def sign_invoice(private_key, data):
    return private_key.sign(data, padding.PKCS1v15(), hashes.SHA1())
''', '''
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

def sign_invoice(private_key, data):
    return private_key.sign(data, padding.PKCS1v15(), hashes.SHA256())
''')
P("wh03", C, K, "plain", '''
from Crypto.Hash import SHA1
from Crypto.Signature import pss

def sign_release(rsa_key, artifact):
    return pss.new(rsa_key).sign(SHA1.new(artifact))
''', '''
from Crypto.Hash import SHA256
from Crypto.Signature import pss

def sign_release(rsa_key, artifact):
    return pss.new(rsa_key).sign(SHA256.new(artifact))
''')
P("wh04", C, K, "plain", '''
from Crypto.Hash import SHA1
from Crypto.Signature import pkcs1_15

def signature_is_valid(public_key, data, signature):
    try:
        pkcs1_15.new(public_key).verify(SHA1.new(data), signature)
        return True
    except ValueError:
        return False
''', '''
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15

def signature_is_valid(public_key, data, signature):
    try:
        pkcs1_15.new(public_key).verify(SHA256.new(data), signature)
        return True
    except ValueError:
        return False
''')
P("wh05", C, K, "plain", '''
from Crypto.Hash import MD5
from Crypto.Signature import pkcs1_15

def sign_document(rsa_key, document):
    h = MD5.new(document)
    return pkcs1_15.new(rsa_key).sign(h)
''', '''
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15

def sign_document(rsa_key, document):
    h = SHA256.new(document)
    return pkcs1_15.new(rsa_key).sign(h)
''')
P("wh06", C, K, "obscured", '''
import hashlib

CONFIG = {"digest": "md5", "chunk": 65536}

def package_digest(path):
    h = hashlib.new(CONFIG["digest"])
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(CONFIG["chunk"]), b""):
            h.update(block)
    return h.hexdigest()

def package_ok(path, published_hex):
    return package_digest(path) == published_hex
''', '''
import hashlib

CONFIG = {"digest": "sha256", "chunk": 65536}

def package_digest(path):
    h = hashlib.new(CONFIG["digest"])
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(CONFIG["chunk"]), b""):
            h.update(block)
    return h.hexdigest()

def package_ok(path, published_hex):
    return package_digest(path) == published_hex
''')
P("wh07", C, K, "obscured", '''
import hashlib, os

def integrity_hash(data):
    algo = getattr(hashlib, os.environ.get("INTEGRITY_HASH", "sha1"))
    return algo(data).hexdigest()
''', '''
import hashlib, os

ALLOWED = {"sha256", "sha384", "sha512"}

def integrity_hash(data):
    name = os.environ.get("INTEGRITY_HASH", "sha256")
    if name not in ALLOWED:
        raise ValueError("unsupported hash")
    return getattr(hashlib, name)(data).hexdigest()
''')
P("wh08", C, K, "obscured", '''
from hashlib import md5 as checksum

def firmware_is_authentic(image, published):
    return checksum(image).hexdigest() == published
''', '''
from hashlib import sha256 as checksum

def firmware_is_authentic(image, published):
    return checksum(image).hexdigest() == published
''')
P("wh09", C, K, "obscured", '''
import hashlib

class ReleaseVerifier:
    def __init__(self, algorithm="sha1"):
        self.algorithm = algorithm

    def verify(self, blob, expected):
        return hashlib.new(self.algorithm, blob).hexdigest() == expected
''', '''
import hashlib

class ReleaseVerifier:
    ALLOWED = {"sha256", "sha384", "sha512"}

    def __init__(self, algorithm="sha256"):
        if algorithm not in self.ALLOWED:
            raise ValueError("unsupported hash")
        self.algorithm = algorithm

    def verify(self, blob, expected):
        return hashlib.new(self.algorithm, blob).hexdigest() == expected
''')
P("wh10", C, K, "obscured", '''
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

HASHES = {"fast": hashes.SHA1(), "strong": hashes.SHA256()}

def sign_report(private_key, report):
    return private_key.sign(report, padding.PKCS1v15(), HASHES["fast"])
''', '''
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

HASHES = {"fast": hashes.SHA1(), "strong": hashes.SHA256()}

def sign_report(private_key, report):
    return private_key.sign(report, padding.PKCS1v15(), HASHES["strong"])
''')

# =====================================================================
# 2. ecb_mode (CWE-327): block cipher in ECB mode. Twins use AEAD.
# =====================================================================
C, K = "CWE-327", "ecb_mode"
P("ecb01", C, K, "plain", '''
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

def encrypt_record(key, record):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(pad(record, 16))
''', '''
from Crypto.Cipher import AES

def encrypt_record(key, record):
    cipher = AES.new(key, AES.MODE_GCM)
    ct, tag = cipher.encrypt_and_digest(record)
    return cipher.nonce + ct + tag
''')
P("ecb02", C, K, "plain", '''
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def encrypt_message(key, msg):
    padder = padding.PKCS7(128).padder()
    data = padder.update(msg) + padder.finalize()
    enc = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return enc.update(data) + enc.finalize()
''', '''
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def encrypt_message(key, msg):
    nonce = os.urandom(12)
    return nonce + AESGCM(key).encrypt(nonce, msg, None)
''')
P("ecb03", C, K, "plain", '''
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

def encrypt_card_number(key, pan):
    return AES.new(key, AES.MODE_ECB).encrypt(pad(pan.encode(), 16))
''', '''
from Crypto.Cipher import AES

def encrypt_card_number(key, pan):
    c = AES.new(key, AES.MODE_GCM)
    ct, tag = c.encrypt_and_digest(pan.encode())
    return c.nonce + ct + tag
''')
P("ecb04", C, K, "plain", '''
from Crypto.Cipher import AES

def encrypt_image(key, pixels):
    cipher = AES.new(key, AES.MODE_ECB)
    out = b""
    for i in range(0, len(pixels), 16):
        out += cipher.encrypt(pixels[i:i + 16].ljust(16, b"\\0"))
    return out
''', '''
from Crypto.Cipher import AES

def encrypt_image(key, pixels):
    cipher = AES.new(key, AES.MODE_GCM)
    ct, tag = cipher.encrypt_and_digest(pixels)
    return cipher.nonce + ct + tag
''')
P("ecb05", C, K, "plain", '''
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

class SessionStore:
    def __init__(self, key):
        self.cipher = AES.new(key, AES.MODE_ECB)

    def seal(self, session_json):
        return self.cipher.encrypt(pad(session_json, 16))
''', '''
from Crypto.Cipher import AES

class SessionStore:
    def __init__(self, key):
        self.key = key

    def seal(self, session_json):
        cipher = AES.new(self.key, AES.MODE_GCM)
        ct, tag = cipher.encrypt_and_digest(session_json)
        return cipher.nonce + ct + tag
''')
P("ecb06", C, K, "obscured", '''
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

MODE = 1

def protect(key, data):
    return AES.new(key, MODE).encrypt(pad(data, 16))
''', '''
from Crypto.Cipher import AES

MODE = 11

def protect(key, data):
    cipher = AES.new(key, MODE)
    ct, tag = cipher.encrypt_and_digest(data)
    return cipher.nonce + ct + tag
''')
P("ecb07", C, K, "obscured", '''
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.primitives.ciphers.modes import ECB as BlockMode

def protect(key, data):
    padder = padding.PKCS7(128).padder()
    data = padder.update(data) + padder.finalize()
    enc = Cipher(algorithms.AES(key), BlockMode()).encryptor()
    return enc.update(data) + enc.finalize()
''', '''
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.primitives.ciphers.modes import GCM as BlockMode

def protect(key, data):
    nonce = os.urandom(12)
    enc = Cipher(algorithms.AES(key), BlockMode(nonce)).encryptor()
    ct = enc.update(data) + enc.finalize()
    return nonce + ct + enc.tag
''')
P("ecb08", C, K, "obscured", '''
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

MODES = {"fast": AES.MODE_ECB, "safe": AES.MODE_GCM}

def protect(key, data):
    return AES.new(key, MODES["fast"]).encrypt(pad(data, 16))
''', '''
from Crypto.Cipher import AES

MODES = {"fast": AES.MODE_ECB, "safe": AES.MODE_GCM}

def protect(key, data):
    cipher = AES.new(key, MODES["safe"])
    ct, tag = cipher.encrypt_and_digest(data)
    return cipher.nonce + ct + tag
''')
P("ecb09", C, K, "obscured", '''
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def _block_mode():
    return modes.ECB()

def encrypt_blocks(key, data):
    assert len(data) % 16 == 0
    enc = Cipher(algorithms.AES(key), _block_mode()).encryptor()
    return enc.update(data) + enc.finalize()
''', '''
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def _block_mode(nonce):
    return modes.GCM(nonce)

def encrypt_blocks(key, data):
    nonce = os.urandom(12)
    enc = Cipher(algorithms.AES(key), _block_mode(nonce)).encryptor()
    ct = enc.update(data) + enc.finalize()
    return nonce + ct + enc.tag
''')
P("ecb10", C, K, "obscured", '''
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

SETTINGS = {"cipher_mode": 1, "block": 16}

def encrypt_tokens(key, tokens):
    data = pad(b"".join(tokens), SETTINGS["block"])
    return AES.new(key, SETTINGS["cipher_mode"]).encrypt(data)
''', '''
from Crypto.Cipher import AES

SETTINGS = {"cipher_mode": 11, "block": 16}

def encrypt_tokens(key, tokens):
    cipher = AES.new(key, SETTINGS["cipher_mode"])
    ct, tag = cipher.encrypt_and_digest(b"".join(tokens))
    return cipher.nonce + ct + tag
''')
# =====================================================================
# 3. hardcoded_key (CWE-321): key or secret in source. Twins read it
#    from the environment or a secret file and fail if it is missing.
# =====================================================================
C, K = "CWE-321", "hardcoded_key"
P("hk01", C, K, "plain", '''
from Crypto.Cipher import AES

KEY = b"0123456789abcdef0123456789abcdef"

def encrypt(data):
    cipher = AES.new(KEY, AES.MODE_GCM)
    ct, tag = cipher.encrypt_and_digest(data)
    return cipher.nonce + ct + tag
''', '''
import os
from Crypto.Cipher import AES

KEY = bytes.fromhex(os.environ["DATA_KEY_HEX"])

def encrypt(data):
    cipher = AES.new(KEY, AES.MODE_GCM)
    ct, tag = cipher.encrypt_and_digest(data)
    return cipher.nonce + ct + tag
''')
P("hk02", C, K, "plain", '''
import time
import jwt

JWT_SECRET = "super-secret-jwt-key-2026"

def issue_token(user_id):
    claims = {"sub": str(user_id), "exp": int(time.time()) + 3600}
    return jwt.encode(claims, JWT_SECRET, algorithm="HS256")
''', '''
import os, time
import jwt

JWT_SECRET = os.environ["JWT_SECRET"]

def issue_token(user_id):
    claims = {"sub": str(user_id), "exp": int(time.time()) + 3600}
    return jwt.encode(claims, JWT_SECRET, algorithm="HS256")
''')
P("hk03", C, K, "plain", '''
import hashlib, hmac

WEBHOOK_SECRET = b"whsec_7f3a9c2e4b1d8f60"

def webhook_is_valid(body, signature):
    expected = hmac.new(WEBHOOK_SECRET, body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)
''', '''
import hashlib, hmac, os

WEBHOOK_SECRET = os.environ["WEBHOOK_SECRET"].encode()

def webhook_is_valid(body, signature):
    expected = hmac.new(WEBHOOK_SECRET, body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)
''')
P("hk04", C, K, "plain", '''
from cryptography.fernet import Fernet

FERNET_KEY = b"q1Fv3cJ8yGmX2wR7tLz0pN5sK9dH4bA6eU8iO3uY1cE="

def seal(data):
    return Fernet(FERNET_KEY).encrypt(data)
''', '''
import os
from cryptography.fernet import Fernet

FERNET_KEY = os.environ["FERNET_KEY"].encode()

def seal(data):
    return Fernet(FERNET_KEY).encrypt(data)
''')
P("hk05", C, K, "plain", '''
from flask import Flask

app = Flask(__name__)
app.config["SECRET_KEY"] = "flask-session-signing-key-prod"
''', '''
import os
from flask import Flask

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ["FLASK_SECRET_KEY"]
''')
P("hk06", C, K, "obscured", '''
from Crypto.Cipher import AES

_PARTS = ("prod", "-2026-", "k9f3", "q7w2", "z8x1")
KEY = "".join(_PARTS).encode().ljust(32, b"0")

def encrypt(data):
    cipher = AES.new(KEY, AES.MODE_GCM)
    ct, tag = cipher.encrypt_and_digest(data)
    return cipher.nonce + ct + tag
''', '''
import os
from Crypto.Cipher import AES

KEY = bytes.fromhex(os.environ["DATA_KEY_HEX"])

def encrypt(data):
    cipher = AES.new(KEY, AES.MODE_GCM)
    ct, tag = cipher.encrypt_and_digest(data)
    return cipher.nonce + ct + tag
''')
P("hk07", C, K, "obscured", '''
import base64, hashlib, hmac

def _signing_key():
    return base64.b64decode("c2lnbmluZy1rZXktZm9yLWludm9pY2VzLTIwMjY=")

def sign_invoice(body):
    return hmac.new(_signing_key(), body, hashlib.sha256).hexdigest()
''', '''
import base64, hashlib, hmac, os

def _signing_key():
    return base64.b64decode(os.environ["INVOICE_SIGNING_KEY_B64"])

def sign_invoice(body):
    return hmac.new(_signing_key(), body, hashlib.sha256).hexdigest()
''')
P("hk08", C, K, "obscured", '''
import hashlib, hmac, os

API_SECRET = os.environ.get("API_SECRET", "changeme-7d1e2b").encode()

def sign_request(payload):
    return hmac.new(API_SECRET, payload, hashlib.sha256).hexdigest()
''', '''
import hashlib, hmac, os

API_SECRET = os.environ["API_SECRET"].encode()

def sign_request(payload):
    return hmac.new(API_SECRET, payload, hashlib.sha256).hexdigest()
''')
P("hk09", C, K, "obscured", '''
import time
import jwt

SETTINGS = {
    "db_host": "db.internal",
    "db_port": 5432,
    "token_key": "a8f5f167f44f4964e6c998dee827110c",
    "token_ttl": 3600,
}

def issue_token(user_id):
    claims = {"sub": str(user_id), "exp": int(time.time()) + SETTINGS["token_ttl"]}
    return jwt.encode(claims, SETTINGS["token_key"], algorithm="HS256")
''', '''
import os
import time
import jwt

SETTINGS = {
    "db_host": "db.internal",
    "db_port": 5432,
    "token_key": os.environ["TOKEN_KEY"],
    "token_ttl": 3600,
}

def issue_token(user_id):
    claims = {"sub": str(user_id), "exp": int(time.time()) + SETTINGS["token_ttl"]}
    return jwt.encode(claims, SETTINGS["token_key"], algorithm="HS256")
''')
P("hk10", C, K, "obscured", '''
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEY = hashlib.sha256(b"acme corp internal passphrase").digest()

def encrypt(nonce, data):
    return AESGCM(KEY).encrypt(nonce, data, None)
''', '''
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

with open("/run/secrets/data_key", "rb") as f:
    KEY = f.read(32)

def encrypt(nonce, data):
    return AESGCM(KEY).encrypt(nonce, data, None)
''')

# =====================================================================
# 4. static_iv (CWE-1204): fixed or reused IV / nonce. All AEAD, so the
#    twin differs only in where the nonce comes from.
# =====================================================================
C, K = "CWE-1204", "static_iv"
P("iv01", C, K, "plain", '''
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

NONCE = b"\\x00" * 12

def encrypt(key, data):
    return AESGCM(key).encrypt(NONCE, data, None)
''', '''
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def encrypt(key, data):
    nonce = os.urandom(12)
    return nonce + AESGCM(key).encrypt(nonce, data, None)
''')
P("iv02", C, K, "plain", '''
from Crypto.Cipher import AES

def encrypt(key, data):
    cipher = AES.new(key, AES.MODE_GCM, nonce=b"fixed-nonce!")
    ct, tag = cipher.encrypt_and_digest(data)
    return ct + tag
''', '''
import os
from Crypto.Cipher import AES

def encrypt(key, data):
    nonce = os.urandom(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ct, tag = cipher.encrypt_and_digest(data)
    return nonce + ct + tag
''')
P("iv03", C, K, "plain", '''
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

NONCE = b"123456789012"

def seal(key, msg):
    return ChaCha20Poly1305(key).encrypt(NONCE, msg, None)
''', '''
import os
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

def seal(key, msg):
    nonce = os.urandom(12)
    return nonce + ChaCha20Poly1305(key).encrypt(nonce, msg, None)
''')
P("iv04", C, K, "plain", '''
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def encrypt_for_user(key, user_id, data):
    nonce = user_id.to_bytes(12, "big")
    return AESGCM(key).encrypt(nonce, data, None)
''', '''
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def encrypt_for_user(key, user_id, data):
    nonce = os.urandom(12)
    aad = user_id.to_bytes(8, "big")
    return nonce + AESGCM(key).encrypt(nonce, data, aad)
''')
P("iv05", C, K, "plain", '''
from Crypto.Cipher import AES

def encrypt(key, data):
    iv = key[:16]
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    ct, tag = cipher.encrypt_and_digest(data)
    return ct + tag
''', '''
import os
from Crypto.Cipher import AES

def encrypt(key, data):
    iv = os.urandom(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    ct, tag = cipher.encrypt_and_digest(data)
    return iv + ct + tag
''')
P("iv06", C, K, "obscured", '''
import time
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def encrypt(key, data):
    nonce = int(time.time()).to_bytes(12, "big")
    return nonce + AESGCM(key).encrypt(nonce, data, None)
''', '''
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def encrypt(key, data):
    nonce = os.urandom(12)
    return nonce + AESGCM(key).encrypt(nonce, data, None)
''')
P("iv07", C, K, "obscured", '''
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def encrypt(key, data, nonce=bytes(12)):
    return nonce + AESGCM(key).encrypt(nonce, data, None)
''', '''
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def encrypt(key, data):
    nonce = os.urandom(12)
    return nonce + AESGCM(key).encrypt(nonce, data, None)
''')
P("iv08", C, K, "obscured", '''
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

NONCE = os.urandom(12)

def encrypt(key, data):
    return NONCE + AESGCM(key).encrypt(NONCE, data, None)
''', '''
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def encrypt(key, data):
    nonce = os.urandom(12)
    return nonce + AESGCM(key).encrypt(nonce, data, None)
''')
P("iv09", C, K, "obscured", '''
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def encrypt_file(key, filename, contents):
    nonce = hashlib.sha256(filename.encode()).digest()[:12]
    return nonce + AESGCM(key).encrypt(nonce, contents, None)
''', '''
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def encrypt_file(key, filename, contents):
    nonce = os.urandom(12)
    return nonce + AESGCM(key).encrypt(nonce, contents, filename.encode())
''')
P("iv10", C, K, "obscured", '''
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class MessageEncryptor:
    def __init__(self, key):
        self.aead = AESGCM(key)
        self.nonce = os.urandom(12)

    def encrypt(self, msg):
        return self.nonce + self.aead.encrypt(self.nonce, msg, None)
''', '''
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class MessageEncryptor:
    def __init__(self, key):
        self.aead = AESGCM(key)

    def encrypt(self, msg):
        nonce = os.urandom(12)
        return nonce + self.aead.encrypt(nonce, msg, None)
''')

# =====================================================================
# 5. weak_prng (CWE-338): non-cryptographic randomness for security values.
# =====================================================================
C, K = "CWE-338", "weak_prng"
P("pr01", C, K, "plain", '''
import random

def login_otp():
    return f"{random.randint(0, 999999):06d}"
''', '''
import secrets

def login_otp():
    return f"{secrets.randbelow(1000000):06d}"
''')
P("pr02", C, K, "plain", '''
import random, string

ALPHABET = string.ascii_letters + string.digits

def temporary_password(length=14):
    return "".join(random.choice(ALPHABET) for _ in range(length))
''', '''
import secrets, string

ALPHABET = string.ascii_letters + string.digits

def temporary_password(length=14):
    return "".join(secrets.choice(ALPHABET) for _ in range(length))
''')
P("pr03", C, K, "plain", '''
import random

def new_api_key():
    return f"{random.getrandbits(128):032x}"
''', '''
import secrets

def new_api_key():
    return secrets.token_hex(16)
''')
P("pr04", C, K, "plain", '''
import random

def csrf_token():
    return str(random.random())[2:]
''', '''
import secrets

def csrf_token():
    return secrets.token_urlsafe(32)
''')
P("pr05", C, K, "plain", '''
import numpy as np

def new_encryption_key():
    return np.random.bytes(32)
''', '''
import secrets

def new_encryption_key():
    return secrets.token_bytes(32)
''')
P("pr06", "CWE-330", K, "obscured", '''
import uuid

def new_session_id():
    return uuid.uuid1().hex
''', '''
import uuid

def new_session_id():
    return uuid.uuid4().hex
''')
P("pr07", C, K, "obscured", '''
import random

_rng = random.Random()

def invite_code():
    return "".join(_rng.choice("ABCDEFGHJKLMNPQRSTUVWXYZ23456789") for _ in range(10))
''', '''
import random

_rng = random.SystemRandom()

def invite_code():
    return "".join(_rng.choice("ABCDEFGHJKLMNPQRSTUVWXYZ23456789") for _ in range(10))
''')
P("pr08", C, K, "obscured", '''
from random import choice as pick

def recovery_code():
    return "-".join("".join(pick("0123456789") for _ in range(4)) for _ in range(4))
''', '''
from secrets import choice as pick

def recovery_code():
    return "-".join("".join(pick("0123456789") for _ in range(4)) for _ in range(4))
''')
P("pr09", C, K, "obscured", '''
import hashlib, time

def password_reset_token(email):
    return hashlib.sha256(f"{email}{time.time()}".encode()).hexdigest()
''', '''
import secrets

def password_reset_token(email):
    return secrets.token_hex(32)
''')
P("pr10", C, K, "obscured", '''
import random

def email_verification_code(user_id):
    rng = random.Random(user_id)
    return "".join(str(rng.randrange(10)) for _ in range(8))
''', '''
import secrets

def email_verification_code(user_id):
    return "".join(str(secrets.randbelow(10)) for _ in range(8))
''')

# =====================================================================
# 6. short_key (CWE-326): inadequate key size or curve.
# =====================================================================
C, K = "CWE-326", "short_key"
P("sk01", C, K, "plain", '''
from cryptography.hazmat.primitives.asymmetric import rsa

def new_signing_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=1024)
''', '''
from cryptography.hazmat.primitives.asymmetric import rsa

def new_signing_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=3072)
''')
P("sk02", C, K, "plain", '''
from Crypto.PublicKey import RSA

def new_server_key():
    return RSA.generate(1024).export_key()
''', '''
from Crypto.PublicKey import RSA

def new_server_key():
    return RSA.generate(3072).export_key()
''')
P("sk03", C, K, "plain", '''
from Crypto.PublicKey import ECC

def new_signing_key():
    return ECC.generate(curve="P-192")
''', '''
from Crypto.PublicKey import ECC

def new_signing_key():
    return ECC.generate(curve="P-384")
''')
P("sk04", C, K, "plain", '''
from cryptography.hazmat.primitives.asymmetric import dh

def new_dh_parameters():
    return dh.generate_parameters(generator=2, key_size=512)
''', '''
from cryptography.hazmat.primitives.asymmetric import dh

def new_dh_parameters():
    return dh.generate_parameters(generator=2, key_size=2048)
''')
P("sk05", C, K, "plain", '''
from cryptography.hazmat.primitives.asymmetric import ec

def new_device_key():
    return ec.generate_private_key(ec.SECP192R1())
''', '''
from cryptography.hazmat.primitives.asymmetric import ec

def new_device_key():
    return ec.generate_private_key(ec.SECP256R1())
''')
P("sk06", C, K, "obscured", '''
from Crypto.PublicKey import RSA

KEY_BITS = 1024

def new_tenant_key():
    return RSA.generate(KEY_BITS)
''', '''
from Crypto.PublicKey import RSA

KEY_BITS = 3072

def new_tenant_key():
    return RSA.generate(KEY_BITS)
''')
P("sk07", C, K, "obscured", '''
import os
from cryptography.hazmat.primitives.asymmetric import rsa

def new_key():
    bits = int(os.environ.get("RSA_BITS", "1024"))
    return rsa.generate_private_key(public_exponent=65537, key_size=bits)
''', '''
import os
from cryptography.hazmat.primitives.asymmetric import rsa

def new_key():
    bits = int(os.environ.get("RSA_BITS", "3072"))
    return rsa.generate_private_key(public_exponent=65537, key_size=bits)
''')
P("sk08", C, K, "obscured", '''
from cryptography.hazmat.primitives.asymmetric import rsa

def new_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2 ** 10)
''', '''
from cryptography.hazmat.primitives.asymmetric import rsa

def new_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=3 * 2 ** 10)
''')
P("sk09", C, K, "obscured", '''
from Crypto.PublicKey import RSA

CRYPTO_POLICY = {"rsa": {"bits": 1024, "e": 65537}}

def new_key():
    p = CRYPTO_POLICY["rsa"]
    return RSA.generate(p["bits"], e=p["e"])
''', '''
from Crypto.PublicKey import RSA

CRYPTO_POLICY = {"rsa": {"bits": 4096, "e": 65537}}

def new_key():
    p = CRYPTO_POLICY["rsa"]
    return RSA.generate(p["bits"], e=p["e"])
''')
P("sk10", C, K, "obscured", '''
import hashlib, hmac, os

MAC_KEY = os.urandom(8)

def tag(message):
    return hmac.new(MAC_KEY, message, hashlib.sha256).hexdigest()
''', '''
import hashlib, hmac, os

MAC_KEY = os.urandom(32)

def tag(message):
    return hmac.new(MAC_KEY, message, hashlib.sha256).hexdigest()
''')

# =====================================================================
# 7. broken_cipher (CWE-327): obsolete or non-cipher "encryption".
# =====================================================================
C, K = "CWE-327", "broken_cipher"
P("bc01", C, K, "plain", '''
from Crypto.Cipher import DES

def encrypt(key8, data):
    cipher = DES.new(key8, DES.MODE_EAX)
    ct, tag = cipher.encrypt_and_digest(data)
    return cipher.nonce + ct + tag
''', '''
from Crypto.Cipher import AES

def encrypt(key32, data):
    cipher = AES.new(key32, AES.MODE_EAX)
    ct, tag = cipher.encrypt_and_digest(data)
    return cipher.nonce + ct + tag
''')
P("bc02", C, K, "plain", '''
from Crypto.Cipher import DES3

def encrypt(key24, data):
    cipher = DES3.new(key24, DES3.MODE_EAX)
    ct, tag = cipher.encrypt_and_digest(data)
    return cipher.nonce + ct + tag
''', '''
from Crypto.Cipher import AES

def encrypt(key32, data):
    cipher = AES.new(key32, AES.MODE_EAX)
    ct, tag = cipher.encrypt_and_digest(data)
    return cipher.nonce + ct + tag
''')
P("bc03", C, K, "plain", '''
from Crypto.Cipher import ARC4

def encrypt_stream(key, data):
    return ARC4.new(key).encrypt(data)
''', '''
from Crypto.Cipher import ChaCha20_Poly1305

def encrypt_stream(key, data):
    cipher = ChaCha20_Poly1305.new(key=key)
    ct, tag = cipher.encrypt_and_digest(data)
    return cipher.nonce + ct + tag
''')
P("bc04", C, K, "plain", '''
from Crypto.Cipher import ARC2

def encrypt(key, data):
    cipher = ARC2.new(key, ARC2.MODE_EAX)
    ct, tag = cipher.encrypt_and_digest(data)
    return cipher.nonce + ct + tag
''', '''
from Crypto.Cipher import AES

def encrypt(key, data):
    cipher = AES.new(key, AES.MODE_EAX)
    ct, tag = cipher.encrypt_and_digest(data)
    return cipher.nonce + ct + tag
''')
P("bc05", C, K, "plain", '''
from itertools import cycle

def encrypt_secret(key, data):
    return bytes(a ^ b for a, b in zip(data, cycle(key)))
''', '''
from cryptography.fernet import Fernet

def encrypt_secret(key, data):
    return Fernet(key).encrypt(data)
''')
P("bc06", C, K, "obscured", '''
from Crypto.Cipher import AES, DES3

CIPHERS = {"legacy": DES3, "modern": AES}

def encrypt(key, data, profile="legacy"):
    algo = CIPHERS[profile]
    cipher = algo.new(key, algo.MODE_EAX)
    ct, tag = cipher.encrypt_and_digest(data)
    return cipher.nonce + ct + tag
''', '''
from Crypto.Cipher import AES

CIPHERS = {"modern": AES}

def encrypt(key, data, profile="modern"):
    algo = CIPHERS[profile]
    cipher = algo.new(key, algo.MODE_EAX)
    ct, tag = cipher.encrypt_and_digest(data)
    return cipher.nonce + ct + tag
''')
P("bc07", C, K, "obscured", '''
from Crypto.Cipher import ARC4 as StreamCipher

def protect(key, data):
    return StreamCipher.new(key).encrypt(data)
''', '''
from Crypto.Cipher import ChaCha20_Poly1305 as StreamCipher

def protect(key, data):
    cipher = StreamCipher.new(key=key)
    ct, tag = cipher.encrypt_and_digest(data)
    return cipher.nonce + ct + tag
''')
P("bc08", C, K, "obscured", '''
import base64

def store_db_password(conf, password):
    conf["db_password"] = base64.b64encode(password.encode()).decode()
    return conf
''', '''
from cryptography.fernet import Fernet

def store_db_password(conf, password, key):
    conf["db_password"] = Fernet(key).encrypt(password.encode()).decode()
    return conf
''')
P("bc09", C, K, "obscured", '''
import codecs

def obfuscate_api_key(api_key):
    return codecs.encode(api_key, "rot13")
''', '''
from cryptography.fernet import Fernet

def obfuscate_api_key(api_key, key):
    return Fernet(key).encrypt(api_key.encode()).decode()
''')
P("bc10", C, K, "obscured", '''
import importlib

CONFIG = {"cipher": "DES"}

def encrypt(key, data):
    algo = importlib.import_module("Crypto.Cipher." + CONFIG["cipher"])
    cipher = algo.new(key, algo.MODE_EAX)
    ct, tag = cipher.encrypt_and_digest(data)
    return cipher.nonce + ct + tag
''', '''
import importlib

CONFIG = {"cipher": "AES"}

def encrypt(key, data):
    algo = importlib.import_module("Crypto.Cipher." + CONFIG["cipher"])
    cipher = algo.new(key, algo.MODE_EAX)
    ct, tag = cipher.encrypt_and_digest(data)
    return cipher.nonce + ct + tag
''')
# =====================================================================
# 8. no_salt (CWE-759 / CWE-760 / CWE-916): password storage that is
#    unsalted, statically salted, or too fast.
# =====================================================================
K = "no_salt"
P("ns01", "CWE-759", K, "plain", '''
import hashlib

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()
''', '''
import bcrypt

def hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt())
''')
P("ns02", "CWE-759", K, "plain", '''
import hashlib

def hash_password(password):
    return hashlib.sha512(password.encode()).hexdigest()
''', '''
from argon2 import PasswordHasher

_ph = PasswordHasher()

def hash_password(password):
    return _ph.hash(password)
''')
P("ns03", "CWE-916", K, "plain", '''
import hashlib, os

def hash_password(password):
    salt = os.urandom(16)
    return salt, hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 1000)
''', '''
import hashlib, os

def hash_password(password):
    salt = os.urandom(16)
    return salt, hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 600000)
''')
P("ns04", "CWE-760", K, "plain", '''
import hashlib

SALT = b"static-app-salt"

def hash_password(password):
    return hashlib.pbkdf2_hmac("sha256", password.encode(), SALT, 600000)
''', '''
import hashlib, os

def hash_password(password):
    salt = os.urandom(16)
    return salt, hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 600000)
''')
P("ns05", "CWE-916", K, "plain", '''
import hashlib, os

def hash_password(password):
    salt = os.urandom(16)
    return salt, hashlib.sha256(salt + password.encode()).digest()
''', '''
import hashlib, os

def hash_password(password):
    salt = os.urandom(16)
    return salt, hashlib.scrypt(password.encode(), salt=salt, n=2 ** 15, r=8, p=1, maxmem=2 ** 26)
''')
P("ns06", "CWE-759", K, "obscured", '''
import hashlib

PW_HASH = "sha3_256"

def hash_password(password):
    return hashlib.new(PW_HASH, password.encode()).hexdigest()
''', '''
import bcrypt

def hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))
''')
P("ns07", "CWE-759", K, "obscured", '''
from hashlib import blake2b

def hash_password(password):
    return blake2b(password.encode(), digest_size=32).hexdigest()
''', '''
from argon2 import PasswordHasher

_ph = PasswordHasher()

def hash_password(password):
    return _ph.hash(password)
''')
P("ns08", "CWE-760", K, "obscured", '''
import hashlib

def hash_password(username, password):
    salt = username.lower().encode()
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 600000)
''', '''
import hashlib, os

def hash_password(username, password):
    salt = os.urandom(16)
    return salt, hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 600000)
''')
P("ns09", "CWE-916", K, "obscured", '''
import hashlib, hmac, os

PEPPER = os.environ["PASSWORD_PEPPER"].encode()

def hash_password(password):
    return hmac.new(PEPPER, password.encode(), hashlib.sha256).hexdigest()
''', '''
import hashlib, hmac, os
from argon2 import PasswordHasher

PEPPER = os.environ["PASSWORD_PEPPER"].encode()
_ph = PasswordHasher()

def hash_password(password):
    peppered = hmac.new(PEPPER, password.encode(), hashlib.sha256).hexdigest()
    return _ph.hash(peppered)
''')
P("ns10", "CWE-916", K, "obscured", '''
import hashlib, os

KDF_ITERATIONS = int(os.environ.get("KDF_ITERATIONS", "1000"))

def hash_password(password):
    salt = os.urandom(16)
    return salt, hashlib.pbkdf2_hmac("sha256", password.encode(), salt, KDF_ITERATIONS)
''', '''
import hashlib, os

KDF_ITERATIONS = int(os.environ.get("KDF_ITERATIONS", "600000"))

def hash_password(password):
    salt = os.urandom(16)
    return salt, hashlib.pbkdf2_hmac("sha256", password.encode(), salt, KDF_ITERATIONS)
''')

# =====================================================================
# 9. cert_verify (CWE-295): TLS / host verification disabled. Twins keep
#    verification on and set a timeout, so nothing else is wrong.
# =====================================================================
C, K = "CWE-295", "cert_verify"
P("cv01", C, K, "plain", '''
import requests

def post_payment(url, payload):
    return requests.post(url, json=payload, timeout=10, verify=False).json()
''', '''
import requests

def post_payment(url, payload):
    return requests.post(url, json=payload, timeout=10).json()
''')
P("cv02", C, K, "plain", '''
import httpx

def make_client():
    return httpx.Client(verify=False, timeout=10.0)
''', '''
import httpx

def make_client():
    return httpx.Client(timeout=10.0)
''')
P("cv03", C, K, "plain", '''
import urllib3

def make_pool():
    return urllib3.PoolManager(cert_reqs="CERT_NONE", timeout=10.0)
''', '''
import urllib3

def make_pool():
    return urllib3.PoolManager(cert_reqs="CERT_REQUIRED", timeout=10.0)
''')
P("cv04", C, K, "plain", '''
import aiohttp

async def fetch_json(url):
    timeout = aiohttp.ClientTimeout(total=10)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        async with session.get(url, ssl=False) as resp:
            return await resp.json()
''', '''
import aiohttp

async def fetch_json(url):
    timeout = aiohttp.ClientTimeout(total=10)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        async with session.get(url) as resp:
            return await resp.json()
''')
P("cv05", C, K, "plain", '''
import socket, ssl

def open_tls(host, port=443):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    sock = socket.create_connection((host, port), timeout=10)
    return ctx.wrap_socket(sock, server_hostname=host)
''', '''
import socket, ssl

def open_tls(host, port=443):
    ctx = ssl.create_default_context()
    sock = socket.create_connection((host, port), timeout=10)
    return ctx.wrap_socket(sock, server_hostname=host)
''')
P("cv06", C, K, "obscured", '''
import os
import requests

VERIFY_TLS = os.environ.get("VERIFY_TLS", "0") == "1"

def fetch(url):
    return requests.get(url, timeout=10, verify=VERIFY_TLS).text
''', '''
import os
import requests

VERIFY_TLS = os.environ.get("VERIFY_TLS", "1") == "1"

def fetch(url):
    return requests.get(url, timeout=10, verify=VERIFY_TLS).text
''')
P("cv07", C, K, "obscured", '''
import requests

REQUEST_OPTS = {"timeout": 10, "verify": False, "allow_redirects": True}

def fetch(url):
    return requests.get(url, **REQUEST_OPTS).text
''', '''
import requests

REQUEST_OPTS = {"timeout": 10, "verify": True, "allow_redirects": True}

def fetch(url):
    return requests.get(url, **REQUEST_OPTS).text
''')
P("cv08", C, K, "obscured", '''
import socket, ssl

def open_tls(host, port=443):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS)
    sock = socket.create_connection((host, port), timeout=10)
    return ctx.wrap_socket(sock, server_hostname=host)
''', '''
import socket, ssl

def open_tls(host, port=443):
    ctx = ssl.create_default_context()
    sock = socket.create_connection((host, port), timeout=10)
    return ctx.wrap_socket(sock, server_hostname=host)
''')
P("cv09", C, K, "obscured", '''
import requests

def fetch(url, verify_tls=False):
    return requests.get(url, timeout=10, verify=verify_tls).text
''', '''
import requests

def fetch(url, verify_tls=True):
    return requests.get(url, timeout=10, verify=verify_tls).text
''')
P("cv10", C, K, "obscured", '''
import socket, ssl

TLS_SETTINGS = {"check_hostname": False, "verify_mode": 0}

def open_tls(host, port=443):
    ctx = ssl.create_default_context()
    ctx.check_hostname = TLS_SETTINGS["check_hostname"]
    ctx.verify_mode = ssl.VerifyMode(TLS_SETTINGS["verify_mode"])
    sock = socket.create_connection((host, port), timeout=10)
    return ctx.wrap_socket(sock, server_hostname=host)
''', '''
import socket, ssl

TLS_SETTINGS = {"check_hostname": True, "verify_mode": 2}

def open_tls(host, port=443):
    ctx = ssl.create_default_context()
    ctx.check_hostname = TLS_SETTINGS["check_hostname"]
    ctx.verify_mode = ssl.VerifyMode(TLS_SETTINGS["verify_mode"])
    sock = socket.create_connection((host, port), timeout=10)
    return ctx.wrap_socket(sock, server_hostname=host)
''')
# Obscured pairs where the bad name is still in the file, only moved off the
# call site (alias / dict / helper). Analysed separately as "alias-only".
ALIAS_ONLY = {"wh08", "wh10", "ecb07", "ecb08", "ecb09", "bc06", "bc07", "pr07", "pr08", "cv07"}

# Known secondary notes (vuln side only, do not change the correct verdict):
# ecb04 zero padding; ECB pairs lack integrity; bc03/bc07 RC4 key reuse.
# wh10 secure twin keeps hashes.SHA1() as unused dict entry on purpose.
# ns09: HMAC-pepper is unsalted and fast (OWASP: pepper supplements a slow KDF).
# pr06: uuid1 is CWE-330 (predictable identifier), kept in the weak_prng class.

def samples():
    out = []
    for p in PAIRS:
        for label, code in (("vuln", p["vuln"]), ("secure", p["secure"])):
            variant = "alias_only" if p["pid"] in ALIAS_ONLY else p["variant"]
            out.append(dict(id=f'{p["pid"]}_{"v" if label == "vuln" else "s"}', pair=p["pid"],
                            cwe=p["cwe"], category=p["category"], variant=variant,
                            label=label, code=code))
    return out
