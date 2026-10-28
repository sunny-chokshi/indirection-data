from textwrap import dedent
CP = []
def C(src, variant, vuln, secure):
    CP.append(dict(src=src, variant=variant, vuln=dedent(vuln).lstrip("\n"), secure=dedent(secure).lstrip("\n")))

C("wh01", "obscured", '''
import hashlib

DIGEST = "md5"

def verify_download(path, expected_hex):
    with open(path, "rb") as f:
        digest = hashlib.new(DIGEST, f.read()).hexdigest()
    return digest == expected_hex
''', '''
import hashlib

DIGEST = "sha256"

def verify_download(path, expected_hex):
    with open(path, "rb") as f:
        digest = hashlib.new(DIGEST, f.read()).hexdigest()
    return digest == expected_hex
''')

C("wh02", "obscured", '''
from cryptography.hazmat.primitives.hashes import SHA1 as Digest
from cryptography.hazmat.primitives.asymmetric import padding

def sign_invoice(private_key, data):
    return private_key.sign(data, padding.PKCS1v15(), Digest())
''', '''
from cryptography.hazmat.primitives.hashes import SHA256 as Digest
from cryptography.hazmat.primitives.asymmetric import padding

def sign_invoice(private_key, data):
    return private_key.sign(data, padding.PKCS1v15(), Digest())
''')

C("wh03", "obscured", '''
from Crypto.Hash import SHA1 as _H
from Crypto.Signature import pss

def _digest(data):
    return _H.new(data)

def sign_release(rsa_key, artifact):
    return pss.new(rsa_key).sign(_digest(artifact))
''', '''
from Crypto.Hash import SHA256 as _H
from Crypto.Signature import pss

def _digest(data):
    return _H.new(data)

def sign_release(rsa_key, artifact):
    return pss.new(rsa_key).sign(_digest(artifact))
''')

C("wh04", "obscured", '''
import importlib
from Crypto.Signature import pkcs1_15

CONFIG = {"hash": "SHA1"}
Digest = importlib.import_module("Crypto.Hash." + CONFIG["hash"])

def signature_is_valid(public_key, data, signature):
    try:
        pkcs1_15.new(public_key).verify(Digest.new(data), signature)
        return True
    except ValueError:
        return False
''', '''
import importlib
from Crypto.Signature import pkcs1_15

CONFIG = {"hash": "SHA256"}
Digest = importlib.import_module("Crypto.Hash." + CONFIG["hash"])

def signature_is_valid(public_key, data, signature):
    try:
        pkcs1_15.new(public_key).verify(Digest.new(data), signature)
        return True
    except ValueError:
        return False
''')

C("wh05", "obscured", '''
from Crypto.Hash import MD5
from Crypto.Signature import pkcs1_15

def sign_document(rsa_key, document, hash_module=MD5):
    h = hash_module.new(document)
    return pkcs1_15.new(rsa_key).sign(h)
''', '''
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15

def sign_document(rsa_key, document, hash_module=SHA256):
    h = hash_module.new(document)
    return pkcs1_15.new(rsa_key).sign(h)
''')

C("wh06", "plain", '''
import hashlib

CONFIG = {"chunk": 65536}

def package_digest(path):
    h = hashlib.md5()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(CONFIG["chunk"]), b""):
            h.update(block)
    return h.hexdigest()

def package_ok(path, published_hex):
    return package_digest(path) == published_hex
''', '''
import hashlib

CONFIG = {"chunk": 65536}

def package_digest(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(CONFIG["chunk"]), b""):
            h.update(block)
    return h.hexdigest()

def package_ok(path, published_hex):
    return package_digest(path) == published_hex
''')

C("wh07", "plain", '''
import hashlib

def integrity_hash(data):
    return hashlib.sha1(data).hexdigest()
''', '''
import hashlib

def integrity_hash(data):
    return hashlib.sha256(data).hexdigest()
''')

C("wh08", "plain", '''
import hashlib

def firmware_is_authentic(image, published):
    return hashlib.md5(image).hexdigest() == published
''', '''
import hashlib

def firmware_is_authentic(image, published):
    return hashlib.sha256(image).hexdigest() == published
''')

C("wh09", "plain", '''
import hashlib

class ReleaseVerifier:
    def __init__(self, algorithm="sha1"):
        self.algorithm = algorithm

    def verify(self, blob, expected):
        return hashlib.sha1(blob).hexdigest() == expected
''', '''
import hashlib

class ReleaseVerifier:
    ALLOWED = {"sha256", "sha384", "sha512"}

    def __init__(self, algorithm="sha256"):
        if algorithm not in self.ALLOWED:
            raise ValueError("unsupported hash")
        self.algorithm = algorithm

    def verify(self, blob, expected):
        return hashlib.sha256(blob).hexdigest() == expected
''')

C("wh10", "plain", '''
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

def sign_report(private_key, report):
    return private_key.sign(report, padding.PKCS1v15(), hashes.SHA1())
''', '''
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

def sign_report(private_key, report):
    return private_key.sign(report, padding.PKCS1v15(), hashes.SHA256())
''')

C("ecb01", "obscured", '''
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

def encrypt_record(key, record, mode=AES.MODE_ECB):
    cipher = AES.new(key, mode)
    return cipher.encrypt(pad(record, 16))
''', '''
from Crypto.Cipher import AES

def encrypt_record(key, record, mode=AES.MODE_GCM):
    cipher = AES.new(key, mode)
    ct, tag = cipher.encrypt_and_digest(record)
    return cipher.nonce + ct + tag
''')

C("ecb02", "obscured", '''
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

CONFIG = {"mode": "ECB"}

def encrypt_message(key, msg):
    padder = padding.PKCS7(128).padder()
    data = padder.update(msg) + padder.finalize()
    enc = Cipher(algorithms.AES(key), getattr(modes, CONFIG["mode"])()).encryptor()
    return enc.update(data) + enc.finalize()
''', '''
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

CONFIG = {"mode": "GCM"}

def encrypt_message(key, msg):
    nonce = os.urandom(12)
    enc = Cipher(algorithms.AES(key), getattr(modes, CONFIG["mode"])(nonce)).encryptor()
    ct = enc.update(msg) + enc.finalize()
    return nonce + ct + enc.tag
''')

C("ecb03", "obscured", '''
from Crypto.Cipher import AES
from Crypto.Cipher.AES import MODE_ECB as CIPHER_MODE
from Crypto.Util.Padding import pad

def encrypt_card_number(key, pan):
    return AES.new(key, CIPHER_MODE).encrypt(pad(pan.encode(), 16))
''', '''
from Crypto.Cipher import AES
from Crypto.Cipher.AES import MODE_GCM as CIPHER_MODE

def encrypt_card_number(key, pan):
    c = AES.new(key, CIPHER_MODE)
    ct, tag = c.encrypt_and_digest(pan.encode())
    return c.nonce + ct + tag
''')

C("ecb04", "obscured", '''
from Crypto.Cipher import AES

CIPHER_MODE = 1

def encrypt_image(key, pixels):
    cipher = AES.new(key, CIPHER_MODE)
    out = b""
    for i in range(0, len(pixels), 16):
        out += cipher.encrypt(pixels[i:i + 16].ljust(16, b"\\0"))
    return out
''', '''
from Crypto.Cipher import AES

CIPHER_MODE = 11

def encrypt_image(key, pixels):
    cipher = AES.new(key, CIPHER_MODE)
    ct, tag = cipher.encrypt_and_digest(pixels)
    return cipher.nonce + ct + tag
''')

C("ecb05", "obscured", '''
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

SETTINGS = {"mode": "ECB"}

def _make_cipher(key):
    return AES.new(key, getattr(AES, "MODE_" + SETTINGS["mode"]))

class SessionStore:
    def __init__(self, key):
        self.cipher = _make_cipher(key)

    def seal(self, session_json):
        return self.cipher.encrypt(pad(session_json, 16))
''', '''
from Crypto.Cipher import AES

SETTINGS = {"mode": "GCM"}

def _make_cipher(key):
    return AES.new(key, getattr(AES, "MODE_" + SETTINGS["mode"]))

class SessionStore:
    def __init__(self, key):
        self.key = key

    def seal(self, session_json):
        cipher = _make_cipher(self.key)
        ct, tag = cipher.encrypt_and_digest(session_json)
        return cipher.nonce + ct + tag
''')

C("ecb06", "plain", '''
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

def protect(key, data):
    return AES.new(key, AES.MODE_ECB).encrypt(pad(data, 16))
''', '''
from Crypto.Cipher import AES

def protect(key, data):
    cipher = AES.new(key, AES.MODE_GCM)
    ct, tag = cipher.encrypt_and_digest(data)
    return cipher.nonce + ct + tag
''')

C("ecb07", "plain", '''
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def protect(key, data):
    padder = padding.PKCS7(128).padder()
    data = padder.update(data) + padder.finalize()
    enc = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return enc.update(data) + enc.finalize()
''', '''
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def protect(key, data):
    nonce = os.urandom(12)
    enc = Cipher(algorithms.AES(key), modes.GCM(nonce)).encryptor()
    ct = enc.update(data) + enc.finalize()
    return nonce + ct + enc.tag
''')

C("ecb08", "plain", '''
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

def protect(key, data):
    return AES.new(key, AES.MODE_ECB).encrypt(pad(data, 16))
''', '''
from Crypto.Cipher import AES

def protect(key, data):
    cipher = AES.new(key, AES.MODE_GCM)
    ct, tag = cipher.encrypt_and_digest(data)
    return cipher.nonce + ct + tag
''')

C("ecb09", "plain", '''
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def encrypt_blocks(key, data):
    assert len(data) % 16 == 0
    enc = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return enc.update(data) + enc.finalize()
''', '''
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def encrypt_blocks(key, data):
    nonce = os.urandom(12)
    enc = Cipher(algorithms.AES(key), modes.GCM(nonce)).encryptor()
    ct = enc.update(data) + enc.finalize()
    return nonce + ct + enc.tag
''')

C("ecb10", "plain", '''
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

SETTINGS = {"block": 16}

def encrypt_tokens(key, tokens):
    data = pad(b"".join(tokens), SETTINGS["block"])
    return AES.new(key, AES.MODE_ECB).encrypt(data)
''', '''
from Crypto.Cipher import AES

SETTINGS = {"block": 16}

def encrypt_tokens(key, tokens):
    cipher = AES.new(key, AES.MODE_GCM)
    ct, tag = cipher.encrypt_and_digest(b"".join(tokens))
    return cipher.nonce + ct + tag
''')

C("hk01", "obscured", '''
from Crypto.Cipher import AES

KEY = (0x3031323334353637383961626364656630313233343536373839616263646566).to_bytes(32, "big")

def encrypt(data):
    cipher = AES.new(KEY, AES.MODE_GCM)
    ct, tag = cipher.encrypt_and_digest(data)
    return cipher.nonce + ct + tag
''', '''
import os
from Crypto.Cipher import AES

KEY = int(os.environ["DATA_KEY_HEX"], 16).to_bytes(32, "big")

def encrypt(data):
    cipher = AES.new(KEY, AES.MODE_GCM)
    ct, tag = cipher.encrypt_and_digest(data)
    return cipher.nonce + ct + tag
''')

C("hk02", "obscured", '''
import base64, time
import jwt

JWT_SECRET = base64.b64decode("c3VwZXItc2VjcmV0LWp3dC1rZXktMjAyNg==").decode()

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

C("hk03", "obscured", '''
import hashlib, hmac

_PARTS = ("whsec_", "7f3a", "9c2e", "4b1d", "8f60")
WEBHOOK_SECRET = "".join(_PARTS).encode()

def webhook_is_valid(body, signature):
    expected = hmac.new(WEBHOOK_SECRET, body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)
''', '''
import hashlib, hmac, os

_PARTS = (os.environ["WEBHOOK_SECRET"],)
WEBHOOK_SECRET = "".join(_PARTS).encode()

def webhook_is_valid(body, signature):
    expected = hmac.new(WEBHOOK_SECRET, body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)
''')

C("hk04", "obscured", '''
import base64, hashlib
from cryptography.fernet import Fernet

FERNET_KEY = base64.urlsafe_b64encode(hashlib.sha256(b"session sealing material").digest())

def seal(data):
    return Fernet(FERNET_KEY).encrypt(data)
''', '''
import os
from cryptography.fernet import Fernet

FERNET_KEY = os.environ["FERNET_KEY"].encode()

def seal(data):
    return Fernet(FERNET_KEY).encrypt(data)
''')

C("hk05", "obscured", '''
from flask import Flask

DEFAULTS = {"JSON_SORT_KEYS": False, "SECRET_KEY": "flask-session-signing-key-prod", "MAX_CONTENT_LENGTH": 16777216}

app = Flask(__name__)
app.config.from_mapping(DEFAULTS)
''', '''
import os
from flask import Flask

DEFAULTS = {"JSON_SORT_KEYS": False, "SECRET_KEY": os.environ["FLASK_SECRET_KEY"], "MAX_CONTENT_LENGTH": 16777216}

app = Flask(__name__)
app.config.from_mapping(DEFAULTS)
''')

C("hk06", "plain", '''
from Crypto.Cipher import AES

KEY = b"prod-2026-k9f3q7w2z8x10000000000"

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

C("hk07", "plain", '''
import base64, hashlib, hmac

def _signing_key():
    return b"signing-key-for-invoices-2026"

def sign_invoice(body):
    return hmac.new(_signing_key(), body, hashlib.sha256).hexdigest()
''', '''
import base64, hashlib, hmac, os

def _signing_key():
    return base64.b64decode(os.environ["INVOICE_SIGNING_KEY_B64"])

def sign_invoice(body):
    return hmac.new(_signing_key(), body, hashlib.sha256).hexdigest()
''')

C("hk08", "plain", '''
import hashlib, hmac

API_SECRET = b"changeme-7d1e2b"

def sign_request(payload):
    return hmac.new(API_SECRET, payload, hashlib.sha256).hexdigest()
''', '''
import hashlib, hmac, os

API_SECRET = os.environ["API_SECRET"].encode()

def sign_request(payload):
    return hmac.new(API_SECRET, payload, hashlib.sha256).hexdigest()
''')

C("hk09", "plain", '''
import time
import jwt

TOKEN_KEY = "a8f5f167f44f4964e6c998dee827110c"

SETTINGS = {
    "db_host": "db.internal",
    "db_port": 5432,
    "token_ttl": 3600,
}

def issue_token(user_id):
    claims = {"sub": str(user_id), "exp": int(time.time()) + SETTINGS["token_ttl"]}
    return jwt.encode(claims, TOKEN_KEY, algorithm="HS256")
''', '''
import os
import time
import jwt

TOKEN_KEY = os.environ["TOKEN_KEY"]

SETTINGS = {
    "db_host": "db.internal",
    "db_port": 5432,
    "token_ttl": 3600,
}

def issue_token(user_id):
    claims = {"sub": str(user_id), "exp": int(time.time()) + SETTINGS["token_ttl"]}
    return jwt.encode(claims, TOKEN_KEY, algorithm="HS256")
''')

C("hk10", "plain", '''
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEY = b"acme-corp-internal-data-key-2026"

def encrypt(nonce, data):
    return AESGCM(KEY).encrypt(nonce, data, None)
''', '''
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

with open("/run/secrets/data_key", "rb") as f:
    KEY = f.read(32)

def encrypt(nonce, data):
    return AESGCM(KEY).encrypt(nonce, data, None)
''')
