#!/bin/bash
# php2shell (CVE-2026-109618 / CVE-2026-109619) - BIG-IP ASM read-only check.
# Run as root in the BIG-IP advanced shell (bash). It changes nothing.
# Checks: 1) the 3 F5 signatures exist (ASU >= 20261021_191526 installed)
#         2) per policy: enforcement mode, virtual servers, and whether each signature
#            is in the policy, enforced (not staging) and covered by a set with Block on.
python - <<'PYEOF'
# -*- coding: utf-8 -*-
import json, subprocess

SIGS = [200103697, 200204115, 200204113]   # F5 K000163821

def rest(path):
    out = subprocess.check_output(['restcurl', '-u', 'admin:', path])
    return json.loads(out)

def sid_of(link):
    return link.split('/')[-1].split('?')[0]

print('== 1. Signatures on this system (needs ASU 20261021_191526 or later)')
gid = {}
for s in SIGS:
    items = rest('/mgmt/tm/asm/signatures?$filter=signatureId+eq+%d&$select=id,name,accuracy' % s).get('items', [])
    if items:
        gid[s] = items[0]['id']
        print('   %d  OK       %s (accuracy %s)' % (s, items[0]['name'], items[0]['accuracy']))
    else:
        print('   %d  MISSING  -> install the latest ASM attack signature update first' % s)

print('')
print('== 2. Per security policy')
for p in rest('/mgmt/tm/asm/policies?$select=id,fullPath,enforcementMode,virtualServers').get('items', []):
    pid = p['id']
    print('-- %s  mode=%s  vs=%s' % (p['fullPath'], p.get('enforcementMode'), ','.join(p.get('virtualServers') or []) or '(none)'))
    members = {}
    for i in rest('/mgmt/tm/asm/policies/%s/signatures?$top=20000&$select=signatureReference,enabled,performStaging' % pid).get('items', []):
        members[sid_of(i['signatureReference']['link'])] = i
    blocking_sets = []
    for ss in rest('/mgmt/tm/asm/policies/%s/signature-sets' % pid).get('items', []):
        if ss.get('block'):
            ref = rest('/mgmt/tm/asm/signature-sets/%s' % sid_of(ss['signatureSetReference']['link']))
            blocking_sets.append(set(sid_of(r['link']) for r in ref.get('signatureReferences', [])))
    for s in SIGS:
        g = gid.get(s)
        m = members.get(g) if g else None
        if not m:
            verdict = 'NOT IN POLICY'
        elif not m.get('enabled'):
            verdict = 'DISABLED'
        elif m.get('performStaging'):
            verdict = 'STAGING (alarm only, not blocking)'
        elif not any(g in b for b in blocking_sets):
            verdict = 'ENFORCED but no assigned set has Block on'
        else:
            verdict = 'OK (enforced, block)'
        print('   %d  %s' % (s, verdict))
    if p.get('enforcementMode') != 'blocking':
        print('   NOTE: policy is not in Blocking mode, nothing is blocked')
PYEOF
