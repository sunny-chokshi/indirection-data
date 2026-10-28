from textwrap import dedent
CP = []
def C(src, variant, vuln, secure):
    CP.append(dict(src=src, variant=variant, vuln=dedent(vuln).lstrip("\n"), secure=dedent(secure).lstrip("\n")))

C("bc01", "obscured", '''
from Crypto.Cipher import DES

def _block_cipher():
    return DES

def encrypt(key8, data):
    algo = _block_cipher()
    cipher = algo.new(key8, algo.MODE_EAX)
    ct, tag = cipher.encrypt_and_digest(data)
    return cipher.nonce + ct + tag
''', '''
from Crypto.Cipher import AES

def _block_cipher():
    return AES

def encrypt(key32, data):
    algo = _block_cipher()
    cipher = algo.new(key32, algo.MODE_EAX)
    ct, tag = cipher.encrypt_and_digest(data)
    return cipher.nonce + ct + tag
''')

C("bc02", "obscured", '''
from Crypto.Cipher import DES3

def encrypt(key24, data, algo=DES3):
    cipher = algo.new(key24, algo.MODE_EAX)
    ct, tag = cipher.encrypt_and_digest(data)
    return cipher.nonce + ct + tag
''', '''
from Crypto.Cipher import AES

def encrypt(key32, data, algo=AES):
    cipher = algo.new(key32, algo.MODE_EAX)
    ct, tag = cipher.encrypt_and_digest(data)
    return cipher.nonce + ct + tag
''')

C("bc03", "obscured", '''
import importlib

STREAM_CIPHER = "ARC4"

def encrypt_stream(key, data):
    algo = importlib.import_module("Crypto.Cipher." + STREAM_CIPHER)
    return algo.new(key).encrypt(data)
''', '''
import importlib

STREAM_CIPHER = "ChaCha20_Poly1305"

def encrypt_stream(key, data):
    algo = importlib.import_module("Crypto.Cipher." + STREAM_CIPHER)
    cipher = algo.new(key=key)
    ct, tag = cipher.encrypt_and_digest(data)
    return cipher.nonce + ct + tag
''')

C("bc04", "obscured", '''
from Crypto.Cipher import ARC2 as BlockCipher

def encrypt(key, data):
    cipher = BlockCipher.new(key, BlockCipher.MODE_EAX)
    ct, tag = cipher.encrypt_and_digest(data)
    return cipher.nonce + ct + tag
''', '''
from Crypto.Cipher import AES as BlockCipher

def encrypt(key, data):
    cipher = BlockCipher.new(key, BlockCipher.MODE_EAX)
    ct, tag = cipher.encrypt_and_digest(data)
    return cipher.nonce + ct + tag
''')

C("bc05", "obscured", '''
from itertools import cycle
from operator import xor as combine

def encrypt_secret(key, data):
    return bytes(map(combine, data, cycle(key)))
''', '''
from cryptography.fernet import Fernet

def encrypt_secret(key, data):
    return Fernet(key).encrypt(data)
''')

C("bc06", "plain", '''
from Crypto.Cipher import AES, DES3

def encrypt(key, data, profile="default"):
    cipher = DES3.new(key, DES3.MODE_EAX)
    ct, tag = cipher.encrypt_and_digest(data)
    return cipher.nonce + ct + tag
''', '''
from Crypto.Cipher import AES

def encrypt(key, data, profile="default"):
    cipher = AES.new(key, AES.MODE_EAX)
    ct, tag = cipher.encrypt_and_digest(data)
    return cipher.nonce + ct + tag
''')

C("bc07", "plain", '''
from Crypto.Cipher import ARC4

def protect(key, data):
    return ARC4.new(key).encrypt(data)
''', '''
from Crypto.Cipher import ChaCha20_Poly1305

def protect(key, data):
    cipher = ChaCha20_Poly1305.new(key=key)
    ct, tag = cipher.encrypt_and_digest(data)
    return cipher.nonce + ct + tag
''')

C("bc10", "plain", '''
from Crypto.Cipher import DES

CONFIG = {"cipher": "DES"}

def encrypt(key, data):
    cipher = DES.new(key, DES.MODE_EAX)
    ct, tag = cipher.encrypt_and_digest(data)
    return cipher.nonce + ct + tag
''', '''
from Crypto.Cipher import AES

CONFIG = {"cipher": "AES"}

def encrypt(key, data):
    cipher = AES.new(key, AES.MODE_EAX)
    ct, tag = cipher.encrypt_and_digest(data)
    return cipher.nonce + ct + tag
''')

C("ns01", "obscured", '''
import hashlib

PW_DIGEST = "sha256"

def hash_password(password):
    return getattr(hashlib, PW_DIGEST)(password.encode()).hexdigest()
''', '''
import bcrypt

PW_ROUNDS = 12

def hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt(PW_ROUNDS))
''')

C("ns02", "obscured", '''
from hashlib import sha512 as digest

def hash_password(password):
    return digest(password.encode()).hexdigest()
''', '''
from argon2 import PasswordHasher as Hasher

_ph = Hasher()

def hash_password(password):
    return _ph.hash(password)
''')

C("ns03", "obscured", '''
import hashlib, os

PBKDF2_ROUNDS = 10 ** 3

def hash_password(password):
    salt = os.urandom(16)
    return salt, hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ROUNDS)
''', '''
import hashlib, os

PBKDF2_ROUNDS = 6 * 10 ** 5

def hash_password(password):
    salt = os.urandom(16)
    return salt, hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ROUNDS)
''')

C("ns04", "obscured", '''
import hashlib

APP_ID = "billing-service"

def hash_password(password):
    return hashlib.pbkdf2_hmac("sha256", password.encode(), APP_ID.encode(), 600000)
''', '''
import hashlib, os

def hash_password(password):
    salt = os.urandom(16)
    return salt, hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 600000)
''')

C("ns05", "obscured", '''
import hashlib, os

PW_SCHEME = {"name": "sha256"}

def hash_password(password):
    salt = os.urandom(16)
    return salt, hashlib.new(PW_SCHEME["name"], salt + password.encode()).digest()
''', '''
import hashlib, os

PW_SCHEME = {"n": 2 ** 15, "r": 8, "p": 1}

def hash_password(password):
    salt = os.urandom(16)
    return salt, hashlib.scrypt(password.encode(), salt=salt, maxmem=2 ** 26, **PW_SCHEME)
''')

C("ns06", "plain", '''
import hashlib

def hash_password(password):
    return hashlib.sha3_256(password.encode()).hexdigest()
''', '''
import bcrypt

def hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))
''')

C("ns08", "plain", '''
import hashlib

def hash_password(username, password):
    return hashlib.pbkdf2_hmac("sha256", password.encode(), username.lower().encode(), 600000)
''', '''
import hashlib, os

def hash_password(username, password):
    salt = os.urandom(16)
    return salt, hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 600000)
''')

C("ns09", "plain", '''
import hashlib, os

PEPPER = os.environ["PASSWORD_PEPPER"].encode()

def hash_password(password):
    return hashlib.sha256(PEPPER + password.encode()).hexdigest()
''', '''
import hashlib, hmac, os
from argon2 import PasswordHasher

PEPPER = os.environ["PASSWORD_PEPPER"].encode()
_ph = PasswordHasher()

def hash_password(password):
    peppered = hmac.new(PEPPER, password.encode(), hashlib.sha256).hexdigest()
    return _ph.hash(peppered)
''')

C("ns10", "plain", '''
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

C("cv01", "obscured", '''
import requests

VERIFY_CERTS = False

def post_payment(url, payload):
    return requests.post(url, json=payload, timeout=10, verify=VERIFY_CERTS).json()
''', '''
import requests

VERIFY_CERTS = True

def post_payment(url, payload):
    return requests.post(url, json=payload, timeout=10, verify=VERIFY_CERTS).json()
''')

C("cv02", "obscured", '''
import httpx

CLIENT_OPTS = {"verify": False, "timeout": 10.0}

def make_client():
    return httpx.Client(**CLIENT_OPTS)
''', '''
import httpx

CLIENT_OPTS = {"verify": True, "timeout": 10.0}

def make_client():
    return httpx.Client(**CLIENT_OPTS)
''')

C("cv03", "obscured", '''
import urllib3

CERT_MODE = 0

def make_pool():
    return urllib3.PoolManager(cert_reqs=CERT_MODE, timeout=10.0)
''', '''
import urllib3

CERT_MODE = 2

def make_pool():
    return urllib3.PoolManager(cert_reqs=CERT_MODE, timeout=10.0)
''')

C("cv04", "obscured", '''
import aiohttp

GET_OPTS = {"ssl": False}

async def fetch_json(url):
    timeout = aiohttp.ClientTimeout(total=10)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        async with session.get(url, **GET_OPTS) as resp:
            return await resp.json()
''', '''
import aiohttp

GET_OPTS = {"ssl": True}

async def fetch_json(url):
    timeout = aiohttp.ClientTimeout(total=10)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        async with session.get(url, **GET_OPTS) as resp:
            return await resp.json()
''')

C("cv05", "obscured", '''
import socket, ssl

TLS_OPTIONS = {"check_hostname": False}

def open_tls(host, port=443):
    ctx = ssl.create_default_context()
    for name, value in TLS_OPTIONS.items():
        setattr(ctx, name, value)
    sock = socket.create_connection((host, port), timeout=10)
    return ctx.wrap_socket(sock, server_hostname=host)
''', '''
import socket, ssl

TLS_OPTIONS = {"check_hostname": True}

def open_tls(host, port=443):
    ctx = ssl.create_default_context()
    for name, value in TLS_OPTIONS.items():
        setattr(ctx, name, value)
    sock = socket.create_connection((host, port), timeout=10)
    return ctx.wrap_socket(sock, server_hostname=host)
''')

C("cv06", "plain", '''
import requests

def fetch(url):
    return requests.get(url, timeout=10, verify=False).text
''', '''
import requests

def fetch(url):
    return requests.get(url, timeout=10, verify=True).text
''')

C("cv07", "plain", '''
import requests

def fetch(url):
    return requests.get(url, timeout=10, verify=False, allow_redirects=True).text
''', '''
import requests

def fetch(url):
    return requests.get(url, timeout=10, verify=True, allow_redirects=True).text
''')

C("cv08", "plain", '''
import socket, ssl

def open_tls(host, port=443):
    ctx = ssl._create_unverified_context()
    sock = socket.create_connection((host, port), timeout=10)
    return ctx.wrap_socket(sock, server_hostname=host)
''', '''
import socket, ssl

def open_tls(host, port=443):
    ctx = ssl.create_default_context()
    sock = socket.create_connection((host, port), timeout=10)
    return ctx.wrap_socket(sock, server_hostname=host)
''')

C("cv09", "plain", '''
import requests

def fetch(url, verify_tls=False):
    return requests.get(url, timeout=10, verify=False).text
''', '''
import requests

def fetch(url, verify_tls=True):
    return requests.get(url, timeout=10, verify=True).text
''')

C("cv10", "plain", '''
import socket, ssl

def open_tls(host, port=443):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    sock = socket.create_connection((host, port), timeout=10)
    return ctx.wrap_socket(sock, server_hostname=host)
''', '''
import socket, ssl

def open_tls(host, port=443):
    ctx = ssl.create_default_context()
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    sock = socket.create_connection((host, port), timeout=10)
    return ctx.wrap_socket(sock, server_hostname=host)
''')
