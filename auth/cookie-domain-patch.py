#!/usr/bin/env python3
# Patches /opt/icelabor/auth-gate.py:
# - Add Domain=.thesoc.de to set_cookie + clear_cookie
# - Change SameSite=Strict to SameSite=Lax (sonst kein Cross-Subdomain-Redirect)
# Idempotent (kann mehrfach laufen).

import re
P = "/opt/icelabor/auth-gate.py"
src = open(P).read()
orig = src

# Patch set_cookie line (Z. ~632)
# from: cookie = f"{name}={value}; Path={path}; Max-Age={max_age}; HttpOnly; Secure; SameSite=Strict"
# to:   cookie = f"{name}={value}; Path={path}; Domain=.thesoc.de; Max-Age={max_age}; HttpOnly; Secure; SameSite=Lax"
src = src.replace(
    'cookie = f"{name}={value}; Path={path}; Max-Age={max_age}; HttpOnly; Secure; SameSite=Strict"',
    'cookie = f"{name}={value}; Path={path}; Domain=.thesoc.de; Max-Age={max_age}; HttpOnly; Secure; SameSite=Lax"'
)
# Patch clear_cookie
src = src.replace(
    'cookie = f"{name}=; Path={path}; Max-Age=0; HttpOnly; Secure; SameSite=Strict"',
    'cookie = f"{name}=; Path={path}; Domain=.thesoc.de; Max-Age=0; HttpOnly; Secure; SameSite=Lax"'
)

if src == orig:
    print("NO_CHANGE (already patched or pattern not found)")
else:
    # Backup
    open(P + ".bak.preSubdomain", "w").write(orig)
    open(P, "w").write(src)
    print("PATCHED")
