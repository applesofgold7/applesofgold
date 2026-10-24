"""Lock the games page with a password for the public website.

Usage: python3 build/lock.py SOURCE.html PASSWORD [OLD_LOCKED.html] > index.html

SOURCE.html is the unlocked games page (the claude.ai artifact). It never goes in
this repository; only the encrypted index.html does. The password is not stored here.
Pass the current locked index.html as OLD_LOCKED.html to keep its salt: the key each
phone remembers then still works after an update, so nobody is asked for the password again.
The test page (test/index.html) uses the same salt, so one password entry opens both.
"""
import base64, json, os, re, sys, zlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

ITER = 600_000
src, password = sys.argv[1], sys.argv[2]
html = open(src, encoding="utf8").read().encode("utf8")
comp = zlib.compressobj(9, zlib.DEFLATED, -15)
raw = comp.compress(html) + comp.flush()
salt, iv = os.urandom(16), os.urandom(12)
if len(sys.argv) > 3:
    old = json.loads(re.search(r"const LOCK=(\{.*?\});", open(sys.argv[3], encoding="utf8").read()).group(1))
    assert old["iter"] == ITER
    salt = base64.b64decode(old["salt"])
key = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=ITER).derive(password.encode("utf8"))
data = AESGCM(key).encrypt(iv, raw, None)
b = lambda x: base64.b64encode(x).decode()
lock = json.dumps({"iter": ITER, "salt": b(salt), "iv": b(iv), "data": b(data)})
tpl = open(os.path.join(os.path.dirname(__file__), "template.html"), encoding="utf8").read()
assert tpl.count("/*LOCK*/null") == 1
sys.stdout.write(tpl.replace("/*LOCK*/null", lock))
