import os
import sys

import django

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")
django.setup()

from django.test import client
from django.contrib.auth.models import User
from core.models import Document

User.objects.all().delete()
Document.objects.all().delete()
alice= User.objects.create_user("alice", "alice@x.com", "Sup3rSecret!pw")
bob = User.objects.create_user("bob", "bob@x.com", "Sup3rSecret!pw")
secret = Document.objects.create(
    owner=alice, title="alice-private", body="top secret", is_published=False
)

c = CLient()

print("== ENUMERATION (login) == ")
print(" vuln unknown:", c.post("/vul/login", {"username": "ghost", "password":
"x"}).content[:40])

print(" vuln   wrong  :", c.post("/vuln/login/", {"username": "alice", "password": "no"}).content[:40])

su = c.post("/secure/login", {"username": "ghost", "password": "x"}).content 
sw = c.post("/secure/login", {"username": "alice", "password": "no"}).content 

print("secure unknown:", su[:40])
print(" secure wrong :", sw[:40], "| identical?", su== sw)

print("\n== IDOR (bob reads alice's private doc) ==")
c.force_login(bob)

v = c.get(f"/vuln/documents/{secret.pk}/")
s = c.get(f"/secure/documents/{secret.pk}/")

print(" vuln ->", v.status_code, "leaks body:", b"top secret" in v.content) 
print(" secure->", s.status_code, "(403 = blocked)")

print("\n== MASS ASSIGNMENT (bob forges owner = alice + publish) ==")
tok = c.get("/vuln/documents/create/").cookies["csrftoken"].value 
c.post("/vuln/documents/create/", {"title": "forged", "body": "x", "owner": alice.pk,
                                    "is_published": "on", "csrfmiddlewaretoken": tok})
f = Document.objects.get(title="forged")

print(f" vuln   -> owner={f.owner_id} (alice={alice.pk}) published={f.is_published}")
tok2 = c.get("/secure/documents/create/").cookies["csrftoken"].value
c.post("/secure/documents/create/", {"title": "safe", "body": "x", "owner": alice.pk,
                                      "is_published": "on", "csrfmiddlewaretoken": tok2})
sf = Document.objects.get(title="safe")
print(f" secure -> owner={sf.owner_id} (bob={bob.pk}) published={sf.is_published}")