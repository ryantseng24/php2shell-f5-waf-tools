#!/usr/bin/env python3
"""php2shell (CVE-2026-109618 / CVE-2026-109619) WAF verification requests.

Sends harmless requests that carry only the request *shape* the WAF controls look for
(field name, part structure, nesting, framing). No exploit payload, no memory exhaustion:
every body is a few KB. Run it against the virtual server, never straight at production PHP.

Usage:
  python3 php2shell_waf_test.py http://www.example.com/index.php
  python3 php2shell_waf_test.py https://www.example.com/upload.php --insecure
Standard library only, so it runs on any host with Python 3.6+.
"""
import argparse
import http.client
import re
import ssl
import sys
import urllib.parse

BOUNDARY = '----php2shellWafTest7MA4YWxk'
BLOCK_RE = re.compile(r'support ID is:?\s*(?:<[^>]*>)?\s*(\d+)', re.I)


def part(name, value='', filename=None, extra_headers=()):
    disp = f'form-data; name="{name}"'
    if filename is not None:
        disp += f'; filename="{filename}"'
    lines = [f'--{BOUNDARY}', f'Content-Disposition: {disp}']
    if filename is not None:
        lines.append('Content-Type: application/octet-stream')
    lines.extend(extra_headers)
    lines += ['', value]
    return '\r\n'.join(lines) + '\r\n'


def multipart(parts):
    return (''.join(parts) + f'--{BOUNDARY}--\r\n').encode()


MP = f'multipart/form-data; boundary={BOUNDARY}'
FORM = 'application/x-www-form-urlencoded'
NEST = 'a' + '[x]' * 70   # deeper than PHP's default max_input_nesting_level (64)

# (id, expectation, description, method, content-type, body, chunked)
CASES = [
    ('N1', 'pass',  'Normal GET',                                   'GET',  None, None, False),
    ('N2', 'pass',  'Normal form POST (urlencoded)',                'POST', FORM, b'name=test&city=taipei', False),
    ('N3', 'pass',  'Normal multipart upload (1 small file)',       'POST', MP,
     multipart([part('note', 'normal upload'), part('upload', 'hello', 'hello.txt')]), False),
    ('A1', 'block', 'CVE-2026-109619: PHP_SESSION_UPLOAD_PROGRESS in multipart (value)', 'POST', MP,
     multipart([part('PHP_SESSION_UPLOAD_PROGRESS', 'wafcheck'), part('upload', 'x', 'a.txt')]), False),
    ('A2', 'block', 'CVE-2026-109619: PHP_SESSION_UPLOAD_PROGRESS in multipart (empty)', 'POST', MP,
     multipart([part('PHP_SESSION_UPLOAD_PROGRESS', ''), part('upload', 'x', 'a.txt')]), False),
    ('A3', 'block', 'CVE-2026-109618: 300 empty file controls',     'POST', MP,
     multipart([part(f'f{i}', '', '') for i in range(300)]), False),
    ('A4', 'block', 'CVE-2026-109618: one part with 300 extra headers', 'POST', MP,
     multipart([part('note', 'x', extra_headers=[f'X-H{i}: {i}' for i in range(300)])]), False),
    ('A5', 'block', 'CVE-2026-109618: nested parameter name depth 70', 'POST', MP,
     multipart([part(NEST, 'x')]), False),
    ('A6', 'block', 'CVE-2026-109618: chunked multipart without Content-Length', 'POST', MP,
     multipart([part('note', 'x'), part('upload', 'x', 'a.txt')]), True),
]


def send(url, method, ctype, body, chunked, insecure, timeout):
    u = urllib.parse.urlsplit(url)
    path = (u.path or '/') + (('?' + u.query) if u.query else '')
    if u.scheme == 'https':
        ctx = ssl._create_unverified_context() if insecure else ssl.create_default_context()
        conn = http.client.HTTPSConnection(u.hostname, u.port or 443, timeout=timeout, context=ctx)
    else:
        conn = http.client.HTTPConnection(u.hostname, u.port or 80, timeout=timeout)
    headers = {'User-Agent': 'php2shell-waf-test/1.0', 'Accept': '*/*'}
    if ctype:
        headers['Content-Type'] = ctype
    if chunked:
        headers['Transfer-Encoding'] = 'chunked'
        conn.putrequest(method, path)
        for k, v in headers.items():
            conn.putheader(k, v)
        conn.endheaders()
        conn.send(f'{len(body):x}\r\n'.encode() + body + b'\r\n0\r\n\r\n')
    else:
        conn.request(method, path, body=body, headers=headers)
    r = conn.getresponse()
    text = r.read().decode('utf-8', 'replace')
    conn.close()
    return r.status, text


def classify(status, text):
    if 'REACHED_PHP=yes' in text:
        return 'REACHED_PHP', ''
    m = BLOCK_RE.search(text)
    if m:
        return 'BLOCKED', m.group(1)
    if 'Request Rejected' in text or 'requested URL was rejected' in text:
        return 'BLOCKED', '?'
    if status == 411:  # the optional Content-Length iRule answers here, before ASM and PHP
        return 'BLOCKED', '(iRule 411)'
    return f'OTHER({status})', ''


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('url', help='URL of a PHP page behind the WAF virtual server')
    ap.add_argument('--insecure', action='store_true', help='skip TLS certificate check (lab only)')
    ap.add_argument('--only', help='comma-separated case ids, e.g. A1,A2')
    ap.add_argument('--timeout', type=float, default=10)
    a = ap.parse_args()

    only = set(a.only.split(',')) if a.only else None
    print(f'Target: {a.url}\n')
    print(f'{"ID":<4}{"Expect":<8}{"Result":<14}{"HTTP":<6}{"Support ID":<22}Description')
    bad = 0
    for cid, expect, desc, method, ctype, body, chunked in CASES:
        if only and cid not in only:
            continue
        try:
            status, text = send(a.url, method, ctype, body, chunked, a.insecure, a.timeout)
            result, sid = classify(status, text)
        except Exception as e:  # a reset connection is a valid blocking response style
            status, result, sid = '-', f'ERR:{type(e).__name__}', ''
        ok = (expect == 'pass' and result == 'REACHED_PHP') or (expect == 'block' and result == 'BLOCKED')
        bad += 0 if ok else 1
        mark = 'OK ' if ok else 'NG '
        print(f'{cid:<4}{expect:<8}{result:<14}{str(status):<6}{sid:<22}{mark}{desc}')
    print(f'\n{"All cases matched expectation." if not bad else f"{bad} case(s) did NOT match expectation."}')
    sys.exit(1 if bad else 0)


if __name__ == '__main__':
    main()
