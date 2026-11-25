#!/usr/bin/env python3
"""Run every WAF rule against adversarial input in PCRE2, with and without JIT.

Upstream treats a regex error, such as the PCRE match limit, as no match, so a
rule that backtracks on a long value lets the attack through.
config/waf-ban.lua runs the query rules on body fields of up to 131072 bytes,
so query rules are checked at that size, and URI and header rules at 8 KB.
The rules are compiled the way tests/test-rules.lua mirrors upstream.
Prints PASS and exits 0, or one FAIL line per failure and exits 1.
"""

import ctypes
import os
import random
import re
import subprocess
import sys
import time

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
LIMIT_MS = 250
SIZES = {"uri": 8192, "query": 131072, "header": 8192, "xml": 131072}
UNITS = [
    b"a",
    b"'",
    b'"',
    b"<a",
    b"${",
    b"${:",
    b"1 or ",
    b"1 ",
    b" on",
    b'" onabc',
    b"/etc/",
    b"&cat ",
    b"union ",
    b"{{",
    b"(",
    b"substr(a,1",
    b" ",
    b'<a"',
    b"=",
    b"&",
    b"/*",
    b"/**/",
    b"')/**/and/**/",
    b"order by 1 ",
    b"sleep/**/",
    b"(/*!0",
    b"(/**/",
    b"into/**/",
    b"://0x1.",
    b"://127.1.",
    b"://0.",
    b"/images/docs/",
    b"%2e",
    b".%2e",
    b"http://a@",
    b"://127.0x",
    b"file:",
    b'"j\t',
    b'"on',
    b"<?",
    b"<!",
    b"${t",
    b";cat a/",
    b"&cat a/b.",
    b"(/***",
    b"1/***",
    b"sleep/***",
    b"1/***/or/***/",
    b";drop ",
    b"/uploaded_files/",
    b"${(",
    b"getClass().",
    b"<java ",
    b"<object ",
    b"<ns:include ",
    b"<!doctype ",
    b"<script",
    b"<#assign",
]
ALPHABET = b"a'\"<>=(){}$:;|&/.-_ 01on\n%,"
CANARY = rb"^(?i)(?s).*\$\{(?:jndi|[^}]*:[^}]*\}).*$"

CHUNK = r"""
dofile("config/waf-local-overrides.lua")
local g = localized_global
local function shim(p)
	return (p:gsub("^%%%.%%*", ".*"):gsub("%%%.%%*%$", ".*"):gsub("%%%.", "."))
end
local function hex(s)
	return (s:gsub(".", function(c) return string.format("%02x", c:byte()) end))
end
for i, r in ipairs(g.WAF_URI_Request_table) do
	print("uri", i, hex("(?i)" .. shim(r[2])))
end
for i, r in ipairs(g.WAF_query_string_Request_table) do
	local v = shim(r[2]):gsub("%%_", "_")
	v = (v == ".*" or v == "^.*$") and ".*" or v:gsub(" ", "[ +%%20]*")
	print("query", i, hex("^(?i)" .. v .. "$"))
end
for i, r in ipairs(g.WAF_Header_Request_table) do
	print("header", i, hex(shim(r[2])))
end
"""

lib = ctypes.CDLL("libpcre2-8.so.0")
P = ctypes.c_void_p
lib.pcre2_compile_8.restype = P
lib.pcre2_compile_8.argtypes = [
    ctypes.c_char_p,
    ctypes.c_size_t,
    ctypes.c_uint32,
    ctypes.POINTER(ctypes.c_int),
    ctypes.POINTER(ctypes.c_size_t),
    P,
]
lib.pcre2_jit_compile_8.argtypes = [P, ctypes.c_uint32]
lib.pcre2_match_data_create_from_pattern_8.restype = P
lib.pcre2_match_data_create_from_pattern_8.argtypes = [P, P]
lib.pcre2_match_8.argtypes = [
    P,
    ctypes.c_char_p,
    ctypes.c_size_t,
    ctypes.c_size_t,
    ctypes.c_uint32,
    P,
    P,
]


def rules():
    """Return (kind, index, pattern, size) for every URI, query, header, and XML rule."""
    out = subprocess.run(
        ["lua", "-e", CHUNK], cwd=ROOT, check=True, capture_output=True
    ).stdout.decode()
    result = []
    for line in out.splitlines():
        kind, index, pattern = line.split("\t")
        result.append((kind, int(index), bytes.fromhex(pattern), SIZES[kind]))
    with open(os.path.join(ROOT, "config", "waf-ban.lua"), encoding="utf-8") as f:
        match = re.search(r"local\s+XML_RULE\s*=\s*\[\[(.*?)\]\]", f.read(), re.S)
    if not match:
        raise ValueError("XML_RULE not found in config/waf-ban.lua")
    result.append(("xml", 1, match.group(1).encode("latin1"), SIZES["xml"]))
    return result


def inputs(size):
    """Return each unit repeated up to size bytes, plus one seeded random string."""
    rng = random.Random(7)
    return [u * (size // len(u)) for u in UNITS] + [
        bytes(rng.choice(ALPHABET) for _ in range(size))
    ]


def compile_(pattern, jit):
    """Compile with options 0 as ngx.re.find does, adding JIT when asked."""
    err, off = ctypes.c_int(), ctypes.c_size_t()
    code = lib.pcre2_compile_8(
        pattern, len(pattern), 0, ctypes.byref(err), ctypes.byref(off), None
    )
    if not code:
        raise ValueError(f"pattern does not compile at offset {off.value}: {pattern!r}")
    if jit and lib.pcre2_jit_compile_8(code, 1) != 0:
        raise ValueError(f"pattern does not JIT-compile: {pattern!r}")
    return code, lib.pcre2_match_data_create_from_pattern_8(code, None)


def run(compiled, subject):
    """Match a compiled pattern and return (rc, ms)."""
    code, md = compiled
    start = time.perf_counter()
    rc = lib.pcre2_match_8(code, subject, len(subject), 0, 0, md, None)
    return rc, 1000 * (time.perf_counter() - start)


def check(pattern, subject, jit):
    """Compile and match once with the default match context; return (rc, ms)."""
    return run(compile_(pattern, jit), subject)


def bad(rc, ms):
    return rc < -1 or ms > LIMIT_MS


def main():
    rc, ms = check(CANARY, b"${:" * 2730, False)
    if not bad(rc, ms):
        print("FAIL canary: inputs no longer reach catastrophic backtracking")
        return 1
    cache = {size: inputs(size) for size in set(SIZES.values())}
    failures = 0
    for kind, index, pattern, size in rules():
        for jit in (False, True):
            compiled = compile_(pattern, jit)
            for subject in cache[size]:
                rc, ms = run(compiled, subject)
                if bad(rc, ms):
                    failures += 1
                    mode = "jit" if jit else "interp"
                    print(
                        f"FAIL {kind} {index}: {mode} rc={rc} {ms:.0f} ms on {subject[:12]!r} x {size}"
                    )
    if failures:
        return 1
    print("PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
