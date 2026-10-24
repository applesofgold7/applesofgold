"""Lock the games page with a password for the public website.

Usage: python3 build/lock.py SOURCE.html PASSWORD > index.html

SOURCE.html is the unlocked games page (the claude.ai artifact). It never goes in
this repository; only the encrypted index.html does. The password is not stored here.
"""
import base64, json, os, sys, zlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

ITER = 600_000
src, password = sys.argv[1], sys.argv[2]
html = open(src, encoding="utf8").read().encode("utf8")
comp = zlib.compressobj(9, zlib.DEFLATED, -15)
raw = comp.compress(html) + comp.flush()
salt, iv = os.urandom(16), os.urandom(12)
key = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=ITER).derive(password.encode("utf8"))
data = AESGCM(key).encrypt(iv, raw, None)
b = lambda x: base64.b64encode(x).decode()
lock = json.dumps({"iter": ITER, "salt": b(salt), "iv": b(iv), "data": b(data)})
tpl = open(os.path.join(os.path.dirname(__file__), "template.html"), encoding="utf8").read()
assert tpl.count("/*LOCK*/null") == 1
sys.stdout.write(tpl.replace("/*LOCK*/null", lock))
