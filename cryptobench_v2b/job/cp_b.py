from textwrap import dedent
CP = []
def C(src, variant, vuln, secure):
    CP.append(dict(src=src, variant=variant, vuln=dedent(vuln).lstrip("\n"), secure=dedent(secure).lstrip("\n")))

C("iv01", "obscured", '''
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def _nonce():
    return bytes(12)

def encrypt(key, data):
    return AESGCM(key).encrypt(_nonce(), data, None)
''', '''
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def _nonce():
    return os.urandom(12)

def encrypt(key, data):
    nonce = _nonce()
    return nonce + AESGCM(key).encrypt(nonce, data, None)
''')

C("iv02", "obscured", '''
from Crypto.Cipher import AES

GCM_OPTIONS = {"mode": AES.MODE_GCM, "nonce": b"fixed-nonce!"}

def encrypt(key, data):
    cipher = AES.new(key, **GCM_OPTIONS)
    ct, tag = cipher.encrypt_and_digest(data)
    return ct + tag
''', '''
import os
from Crypto.Cipher import AES

GCM_OPTIONS = {"mode": AES.MODE_GCM}

def encrypt(key, data):
    nonce = os.urandom(12)
    cipher = AES.new(key, nonce=nonce, **GCM_OPTIONS)
    ct, tag = cipher.encrypt_and_digest(data)
    return nonce + ct + tag
''')

C("iv03", "obscured", '''
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

def _nonce():
    return (123456789012).to_bytes(12, "big")

def seal(key, msg):
    nonce = _nonce()
    return ChaCha20Poly1305(key).encrypt(nonce, msg, None)
''', '''
import secrets
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

def _nonce():
    return secrets.randbits(96).to_bytes(12, "big")

def seal(key, msg):
    nonce = _nonce()
    return nonce + ChaCha20Poly1305(key).encrypt(nonce, msg, None)
''')

C("iv04", "obscured", '''
import struct
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def encrypt_for_user(key, user_id, data):
    nonce = struct.pack(">4xQ", user_id)
    return AESGCM(key).encrypt(nonce, data, None)
''', '''
import os, struct
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def encrypt_for_user(key, user_id, data):
    nonce = os.urandom(12)
    aad = struct.pack(">Q", user_id)
    return nonce + AESGCM(key).encrypt(nonce, data, aad)
''')

C("iv05", "obscured", '''
from Crypto.Cipher import AES

def _iv_for(key):
    return key[:16]

def encrypt(key, data):
    iv = _iv_for(key)
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    ct, tag = cipher.encrypt_and_digest(data)
    return ct + tag
''', '''
import os
from Crypto.Cipher import AES

def _iv_for(key):
    return os.urandom(12)

def encrypt(key, data):
    iv = _iv_for(key)
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    ct, tag = cipher.encrypt_and_digest(data)
    return iv + ct + tag
''')

C("iv07", "plain", '''
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

NONCE = b"\\x00" * 12

def encrypt(key, data):
    return NONCE + AESGCM(key).encrypt(NONCE, data, None)
''', '''
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def encrypt(key, data):
    nonce = os.urandom(12)
    return nonce + AESGCM(key).encrypt(nonce, data, None)
''')

C("pr01", "obscured", '''
from random import randint as draw

def login_otp():
    return f"{draw(0, 999999):06d}"
''', '''
from secrets import randbelow as draw

def login_otp():
    return f"{draw(1000000):06d}"
''')

C("pr02", "obscured", '''
import random, string

ALPHABET = string.ascii_letters + string.digits

def temporary_password(length=14, pick=random.choice):
    return "".join(pick(ALPHABET) for _ in range(length))
''', '''
import secrets, string

ALPHABET = string.ascii_letters + string.digits

def temporary_password(length=14, pick=secrets.choice):
    return "".join(pick(ALPHABET) for _ in range(length))
''')

C("pr03", "obscured", '''
from random import getrandbits as _bits

def _token_int():
    return _bits(128)

def new_api_key():
    return f"{_token_int():032x}"
''', '''
from secrets import randbits as _bits

def _token_int():
    return _bits(128)

def new_api_key():
    return f"{_token_int():032x}"
''')

C("pr04", "obscured", '''
from random import random as draw

def csrf_token():
    return str(draw())[2:]
''', '''
from secrets import token_urlsafe as draw

def csrf_token():
    return draw(32)
''')

C("pr05", "obscured", '''
import importlib

KEYGEN = {"module": "numpy.random", "fn": "bytes"}

def new_encryption_key():
    return getattr(importlib.import_module(KEYGEN["module"]), KEYGEN["fn"])(32)
''', '''
import importlib

KEYGEN = {"module": "secrets", "fn": "token_bytes"}

def new_encryption_key():
    return getattr(importlib.import_module(KEYGEN["module"]), KEYGEN["fn"])(32)
''')

C("pr07", "plain", '''
import random

def invite_code():
    return "".join(random.choice("ABCDEFGHJKLMNPQRSTUVWXYZ23456789") for _ in range(10))
''', '''
import random

def invite_code():
    return "".join(random.SystemRandom().choice("ABCDEFGHJKLMNPQRSTUVWXYZ23456789") for _ in range(10))
''')

C("pr08", "plain", '''
import random

def recovery_code():
    return "-".join("".join(random.choice("0123456789") for _ in range(4)) for _ in range(4))
''', '''
import secrets

def recovery_code():
    return "-".join("".join(secrets.choice("0123456789") for _ in range(4)) for _ in range(4))
''')

C("pr10", "plain", '''
import random

def email_verification_code(user_id):
    random.seed(user_id)
    return "".join(str(random.randrange(10)) for _ in range(8))
''', '''
import secrets

def email_verification_code(user_id):
    return "".join(str(secrets.randbelow(10)) for _ in range(8))
''')

C("sk01", "obscured", '''
from cryptography.hazmat.primitives.asymmetric import rsa

def new_signing_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=0x400)
''', '''
from cryptography.hazmat.primitives.asymmetric import rsa

def new_signing_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=0xC00)
''')

C("sk02", "obscured", '''
from Crypto.PublicKey import RSA

KEYGEN = {"modulus": 1024}

def new_server_key():
    return RSA.generate(KEYGEN["modulus"]).export_key()
''', '''
from Crypto.PublicKey import RSA

KEYGEN = {"modulus": 3072}

def new_server_key():
    return RSA.generate(KEYGEN["modulus"]).export_key()
''')

C("sk03", "obscured", '''
from Crypto.PublicKey import ECC

def new_signing_key():
    return ECC.generate(curve="prime192v1")
''', '''
from Crypto.PublicKey import ECC

def new_signing_key():
    return ECC.generate(curve="secp384r1")
''')

C("sk04", "obscured", '''
from cryptography.hazmat.primitives.asymmetric import dh

def new_dh_parameters():
    return dh.generate_parameters(generator=2, key_size=64 * 8)
''', '''
from cryptography.hazmat.primitives.asymmetric import dh

def new_dh_parameters():
    return dh.generate_parameters(generator=2, key_size=256 * 8)
''')

C("sk05", "obscured", '''
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ObjectIdentifier

def new_device_key():
    return ec.generate_private_key(ec.get_curve_for_oid(ObjectIdentifier("1.2.840.10045.3.1.1"))())
''', '''
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ObjectIdentifier

def new_device_key():
    return ec.generate_private_key(ec.get_curve_for_oid(ObjectIdentifier("1.2.840.10045.3.1.7"))())
''')

C("sk06", "plain", '''
from Crypto.PublicKey import RSA

def new_tenant_key():
    return RSA.generate(1024)
''', '''
from Crypto.PublicKey import RSA

def new_tenant_key():
    return RSA.generate(3072)
''')

C("sk07", "plain", '''
from cryptography.hazmat.primitives.asymmetric import rsa

def new_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=1024)
''', '''
from cryptography.hazmat.primitives.asymmetric import rsa

def new_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=3072)
''')

C("sk08", "plain", '''
from cryptography.hazmat.primitives.asymmetric import rsa

def new_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=1024)
''', '''
from cryptography.hazmat.primitives.asymmetric import rsa

def new_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=3072)
''')

C("sk09", "plain", '''
from Crypto.PublicKey import RSA

def new_key():
    return RSA.generate(1024, e=65537)
''', '''
from Crypto.PublicKey import RSA

def new_key():
    return RSA.generate(4096, e=65537)
''')
