#!/bin/bash
# OpenSCAP scan of an image, run INSIDE a container of it:
#   docker run --rm -v "$PWD/tests:/tests:ro" -v "$PWD/scap:/scap:ro" -v "$PWD/out:/out" IMAGE /tests/scap-scan.sh /out
#
# Evaluates the same tailored STIG profile that oscap-im applied at build
# time, in the same mode oscap-im uses (the SCE check engine, with the
# /run/.containerenv marker that tells SCAP content it is looking at a
# bootable container image). Rules about the running kernel, mounted file
# systems or live services are judged by the configuration that will take
# effect at boot, not by the container's own kernel.
#
# If the image lacks the scanner (the stock base image), it is installed
# first; that adds a few packages to the scanned container and is noted in
# the output.
set -u
OUT=${1:-/out}
DS=/usr/share/xml/scap/ssg/content/ssg-cs10-ds.xml
# The tailoring file: /scap/tailoring.xml if the repo's scap/ directory is
# mounted there (needed to scan the stock base image), else the copy the
# hardened image carries.
TAIL=/scap/tailoring.xml
[ -f "$TAIL" ] || TAIL=/usr/share/hardened-linux/scap/tailoring.xml
PROFILE=xccdf_org.ssgproject.content_profile_stig_hardened_linux

if ! rpm -q openscap-scanner scap-security-guide openscap-engine-sce >/dev/null 2>&1; then
  echo "note: installing openscap-scanner, scap-security-guide, openscap-engine-sce and setools-console into this container to scan it"
  dnf -q -y install openscap-scanner scap-security-guide openscap-engine-sce setools-console >/dev/null 2>&1 || exit 1
fi
mkdir -p "$OUT"
touch /run/.containerenv
echo "scanner: $(rpm -q openscap-scanner) / $(rpm -q scap-security-guide)"
echo "profile: $PROFILE (tailoring: $(basename "$TAIL"))"
OSCAP_PREFERRED_ENGINE=SCE oscap xccdf eval --profile "$PROFILE" --tailoring-file "$TAIL" \
  --results-arf "$OUT/arf.xml" --report "$OUT/report.html" "$DS" > "$OUT/oscap-eval.log" 2>&1
echo "oscap exit code: $? (0 = all pass, 2 = at least one rule failed)"

python3 -I - "$OUT/arf.xml" <<'EOF' | tee "$OUT/summary.txt"
import sys, collections, xml.etree.ElementTree as ET
ns = {'x': 'http://checklists.nist.gov/xccdf/1.2'}
root = ET.parse(sys.argv[1]).getroot()
tr = root.find('.//x:TestResult', ns)
c = collections.Counter(); fails = []
titles = {r.get('id'): (r.findtext('x:title', '', ns), r.get('severity')) for r in root.iter('{%s}Rule' % ns['x'])}
for rr in tr.findall('x:rule-result', ns):
    res = rr.findtext('x:result', '', ns); c[res] += 1
    if res in ('fail', 'error', 'unknown'):
        rid = rr.get('idref'); t, sev = titles.get(rid, ('', ''))
        fails.append((res, rr.get('severity') or sev, rid.replace('xccdf_org.ssgproject.content_rule_', ''), t))
score = tr.find('x:score', ns)
print('results:', ', '.join(f'{k} {v}' for k, v in sorted(c.items())))
evaluated = c['pass'] + c['fail'] + c['error'] + c['unknown']
print(f'pass rate of evaluated rules: {c["pass"]}/{evaluated} = {100*c["pass"]/max(evaluated,1):.1f}%')
print(f'XCCDF default score: {float(score.text):.2f} / {float(score.get("maximum")):.0f}')
print('\nrules not passing (result, severity, rule id, title):')
order = {'high': 0, 'medium': 1, 'low': 2, 'unknown': 3}
for f in sorted(fails, key=lambda f: (order.get(f[1], 3), f[2])):
    print(f'  {f[0]:7} {f[1]:7} {f[2]}  -- {f[3]}')
EOF
