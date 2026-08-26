#!/usr/bin/env bash
# elfguard test suite.
#
# Two halves:
#   1. CORRECTNESS — build binaries with known flags, assert the verdicts.
#   2. ROBUSTNESS  — feed the parser garbage and assert it never crashes.
#
# The second half is the one that matters. A parser for untrusted input that
# has only ever been tested on well-formed input has not been tested.

set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$ROOT/elfguard"
TMP="$ROOT/tests/tmp"
PASS=0; FAIL=0

mkdir -p "$TMP"
trap 'rm -rf "$TMP"' EXIT

ok()   { PASS=$((PASS+1)); printf '  \033[32mok\033[0m   %s\n' "$1"; }
bad()  { FAIL=$((FAIL+1)); printf '  \033[31mFAIL\033[0m %s\n' "$1"; }

# assert that scanning $2 yields a line matching $3
expect() {
  local name="$1" file="$2" pattern="$3"
  if "$BIN" -n "$file" 2>&1 | grep -qE "$pattern"; then ok "$name"
  else bad "$name  (expected /$pattern/)"; fi
}

[ -x "$BIN" ] || { echo "build first: make"; exit 1; }

cat > "$TMP/s.c" <<'EOF'
#include <stdio.h>
#include <string.h>
int main(int c, char **v) { char b[64]; if (c > 1) strcpy(b, v[1]); puts(b); return 0; }
EOF

echo
echo "correctness"

if gcc -w -O0 -fno-stack-protector -U_FORTIFY_SOURCE -z execstack -no-pie \
       -z norelro -o "$TMP/weak" "$TMP/s.c" 2>/dev/null; then
  expect "executable stack detected"   "$TMP/weak"   'FAIL.*NX'
  expect "missing PIE detected"        "$TMP/weak"   'FAIL.*PIE'
  expect "missing RELRO detected"      "$TMP/weak"   'FAIL.*RELRO'
  expect "missing canary detected"     "$TMP/weak"   'FAIL.*canary'
  expect "weak binary graded F"        "$TMP/weak"   '\(F\)'
else
  echo "  skip: toolchain refuses the deliberately-weak build"
fi

if gcc -w -O2 -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE -pie \
       -Wl,-z,relro,-z,now -o "$TMP/strong" "$TMP/s.c" 2>/dev/null; then
  expect "NX recognised"               "$TMP/strong" 'PASS.*NX'
  expect "PIE recognised"              "$TMP/strong" 'PASS.*PIE'
  expect "full RELRO recognised"       "$TMP/strong" 'PASS.*RELRO.*Full'
  expect "canary recognised"           "$TMP/strong" 'PASS.*canary'
  expect "hardened binary graded A+"   "$TMP/strong" '\(A\+\)'
fi

if gcc -w -O2 -no-pie -o "$TMP/lazy" "$TMP/s.c" 2>/dev/null; then
  expect "partial RELRO distinguished" "$TMP/lazy"   'WEAK.*RELRO.*Partial'
fi

  # CET is the check the older tooling misses; verify both directions.
  if gcc -w -O2 -fcf-protection=full -o "$TMP/cet" "$TMP/s.c" 2>/dev/null; then
    expect "CET detected when enabled"    "$TMP/cet"  'PASS.*CET'
  fi
  if gcc -w -O2 -fcf-protection=none -o "$TMP/nocet" "$TMP/s.c" 2>/dev/null; then
    expect "CET absence detected"         "$TMP/nocet" 'FAIL.*CET'
  fi

  # FORTIFY is reported as a ratio, so the output must carry a percentage
  # rather than a bare pass/fail.
  expect "fortify reported as coverage"   "$TMP/strong" 'FORTIFY coverage.*%'

echo
echo "input validation"

printf 'not an elf at all, just text padding padding padding padding pad' > "$TMP/text"
expect "plain text rejected"           "$TMP/text"   'bad magic'

head -c 12 /dev/urandom > "$TMP/tiny"
expect "tiny file rejected"            "$TMP/tiny"   'too small'

# valid magic, total garbage after it
{ printf '\177ELF'; head -c 200 /dev/zero; } > "$TMP/hdr0"
"$BIN" -n "$TMP/hdr0" >/dev/null 2>&1
[ $? -le 2 ] && ok "zeroed header handled" || bad "zeroed header handled"

expect "directory without -r"          "$TMP"        'is a directory'

echo
echo "robustness: targeted header corruption"

# Random mutation is good at breadth but bad at aim. These cases hit the exact
# fields the parser has to trust — the table offsets, the entry counts, the
# string-table index — with the values most likely to walk it off the end.
if [ -f "$TMP/strong" ] && command -v python3 >/dev/null; then
  python3 - "$BIN" "$TMP/strong" "$TMP/corrupt" <<'PY'
import struct, subprocess, sys
binp, src, dst = sys.argv[1], sys.argv[2], sys.argv[3]
data = bytearray(open(src, 'rb').read())
cases = {
    'e_phoff = 2^64-256':  (32, struct.pack('<Q', 0xFFFFFFFFFFFFFF00)),
    'e_shoff = 2^64-256':  (40, struct.pack('<Q', 0xFFFFFFFFFFFFFF00)),
    'e_phnum = 65535':     (56, struct.pack('<H', 65535)),
    'e_shnum = 65535':     (60, struct.pack('<H', 65535)),
    'e_shstrndx = 65535':  (62, struct.pack('<H', 65535)),
    'e_phoff at EOF-3':    (32, struct.pack('<Q', len(data) - 3)),
    'e_shoff at EOF-3':    (40, struct.pack('<Q', len(data) - 3)),
    'e_phentsize = 1':     (54, struct.pack('<H', 1)),
}
fail = 0
for name, (off, val) in cases.items():
    d = bytearray(data)
    d[off:off + len(val)] = val
    open(dst, 'wb').write(d)
    r = subprocess.run([binp, '-n', '-e', dst], capture_output=True, text=True)
    out = r.stdout + r.stderr
    crashed = (r.returncode >= 128 or 'AddressSanitizer' in out
               or 'runtime error' in out)
    if crashed:
        fail += 1
        print(f"  \033[31mFAIL\033[0m {name}  (rc={r.returncode})")
    else:
        print(f"  \033[32mok\033[0m   {name}")
sys.exit(1 if fail else 0)
PY
  if [ $? -eq 0 ]; then PASS=$((PASS+8)); else FAIL=$((FAIL+1)); fi
fi

echo
echo "robustness: property-note parser"

# The note walker is the most intricate parsing in the project: nested
# records, two different padding rules, and sizes the file supplies. Random
# mutation rarely lands on those exact fields, so hit them deliberately.
if command -v python3 >/dev/null && \
   gcc -w -O2 -fcf-protection=full -o "$TMP/cet" "$TMP/s.c" 2>/dev/null; then
  python3 - "$BIN" "$TMP/cet" "$TMP/notecorrupt" <<'PY'
import struct, subprocess, sys
binp, src, dst = sys.argv[1], sys.argv[2], sys.argv[3]
base = bytearray(open(src, 'rb').read())

e_phoff     = struct.unpack_from('<Q', base, 32)[0]
e_phentsize = struct.unpack_from('<H', base, 54)[0]
e_phnum     = struct.unpack_from('<H', base, 56)[0]

note = None
for i in range(e_phnum):
    o = e_phoff + i * e_phentsize
    if struct.unpack_from('<I', base, o)[0] == 0x6474e553:   # PT_GNU_PROPERTY
        note = struct.unpack_from('<Q', base, o + 8)[0]
        break

if note is None:
    print("  skip: no PT_GNU_PROPERTY in the test binary")
    sys.exit(0)

cases = {
    'n_namesz = UINT32_MAX':  (note +  0, 0xFFFFFFFF),
    'n_descsz = UINT32_MAX':  (note +  4, 0xFFFFFFFF),
    'n_descsz = 0':           (note +  4, 0),
    'pr_datasz = UINT32_MAX': (note + 20, 0xFFFFFFFF),
    'pr_datasz = 0':          (note + 20, 0),
    'pr_datasz = INT32_MAX':  (note + 20, 0x7FFFFFFF),
}

fail = 0
for name, (off, val) in cases.items():
    d = bytearray(base)
    struct.pack_into('<I', d, off, val)
    open(dst, 'wb').write(d)
    r = subprocess.run([binp, '-n', '-e', dst], capture_output=True, text=True)
    out = r.stdout + r.stderr
    crashed = (r.returncode >= 128 or 'AddressSanitizer' in out
               or 'runtime error' in out)
    # Failing safe means reporting no CET record, never claiming one is
    # present on the strength of a corrupted size field.
    lied = 'PASS' in out and 'CET' in out and 'advertised' in out
    if crashed or lied:
        fail += 1
        print(f"  \033[31mFAIL\033[0m {name} "
              f"({'crash' if crashed else 'false positive'})")
    else:
        print(f"  \033[32mok\033[0m   {name}")
sys.exit(1 if fail else 0)
PY
  if [ $? -eq 0 ]; then PASS=$((PASS+6)); else FAIL=$((FAIL+1)); fi
fi

echo
echo "robustness: truncation sweep"

if [ -f "$TMP/strong" ]; then
  SZ=$(stat -c%s "$TMP/strong" 2>/dev/null || stat -f%z "$TMP/strong")
  T=0
  n=64
  while [ "$n" -lt "$SZ" ]; do
    head -c "$n" "$TMP/strong" > "$TMP/trunc"
    "$BIN" -n -e "$TMP/trunc" >/dev/null 2>&1
    [ $? -ge 128 ] && { T=$((T+1)); echo "     crash at length $n"; }
    n=$((n + 97))
  done
  [ $T -eq 0 ] && ok "every truncation length handled" \
               || bad "$T crashing truncations"
fi

echo
echo "robustness: mutated ELF corpus"

# Take a real binary and flip bytes in the header region, where every
# offset/count the parser trusts actually lives. 400 mutants, no crashes
# allowed. Exit codes 0/1/2 are fine; anything >= 128 is a signal.
if [ -f "$TMP/strong" ]; then
  CRASH=0
  for i in $(seq 1 400); do
    cp "$TMP/strong" "$TMP/m"
    for _ in 1 2 3; do
      off=$((RANDOM % 512))
      printf "$(printf '\\x%02x' $((RANDOM % 256)))" |
        dd of="$TMP/m" bs=1 seek="$off" count=1 conv=notrunc status=none
    done
    "$BIN" -n "$TMP/m" >/dev/null 2>&1
    rc=$?
    if [ $rc -ge 128 ]; then
      CRASH=$((CRASH+1))
      cp "$TMP/m" "$ROOT/tests/crash-$i.bin"
      echo "     signal $((rc-128)) on mutant $i → saved tests/crash-$i.bin"
    fi
  done
  [ $CRASH -eq 0 ] && ok "400 mutated headers, 0 crashes" \
                   || bad "$CRASH crashing mutants"
fi

echo
echo "diff engine"

mkdir -p "$TMP/base" "$TMP/cand"
if gcc -w -O2 -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fcf-protection=full \
       -fPIE -pie -Wl,-z,relro,-z,now -o "$TMP/base/app" "$TMP/s.c" 2>/dev/null &&
   gcc -w -O0 -fno-stack-protector -fcf-protection=none -no-pie \
       -o "$TMP/cand/app" "$TMP/s.c" 2>/dev/null; then

  out=$("$BIN" -n --diff "$TMP/base" "$TMP/cand" 2>&1); rc=$?
  echo "$out" | grep -q "REGRESSED"  && ok "regression detected" \
                                     || bad "regression detected"
  [ $rc -eq 1 ]                      && ok "regression sets exit 1" \
                                     || bad "regression sets exit 1 (got $rc)"

  out=$("$BIN" -n --diff "$TMP/cand" "$TMP/base" 2>&1); rc=$?
  echo "$out" | grep -q "IMPROVED"   && ok "improvement detected" \
                                     || bad "improvement detected"
  [ $rc -eq 0 ]                      && ok "improvement keeps exit 0" \
                                     || bad "improvement keeps exit 0 (got $rc)"

  out=$("$BIN" -n --diff "$TMP/base" "$TMP/base" 2>&1); rc=$?
  echo "$out" | grep -q "no change"  && ok "identical builds report no change" \
                                     || bad "identical builds report no change"
  [ $rc -eq 0 ]                      && ok "no-change keeps exit 0" \
                                     || bad "no-change keeps exit 0"

  # A diff must never invent a change on a check that became undeterminable.
  "$BIN" -n --diff "$TMP/base/app" "$TMP/text" >/dev/null 2>&1
  [ $? -le 2 ]                       && ok "diff against a non-ELF is handled" \
                                     || bad "diff against a non-ELF is handled"
fi

echo
echo "confidence model"

# The load-bearing rule of the whole v3 model: a check that cannot be proven
# must report UNKNOWN, and UNKNOWN must never be scored as a failure. If this
# breaks, every stripped binary silently looks insecure and the diff fills
# with regressions nobody caused.
if gcc -w -O2 -static -fno-stack-protector -o "$TMP/stat" "$TMP/s.c" 2>/dev/null; then
  strip "$TMP/stat" 2>/dev/null
  out=$("$BIN" -n --explain "$TMP/stat" 2>&1)
  echo "$out" | grep -q '\[ ?  \]' && ok "stripped binary yields UNKNOWN" \
                                     || bad "stripped binary yields UNKNOWN"
  echo "$out" | grep -qi "confidence: LOW" && ok "LOW confidence reported" \
                                           || bad "LOW confidence reported"

  # Assert the rule directly rather than by comparing two binaries' scores.
  #
  # The tempting version of this test — build one stripped and one not, then
  # compare scores — is confounded and was wrong here for a while: a *static*
  # binary links libc, and libc itself references __stack_chk_fail, so the
  # unstripped build reports PASS no matter what -fno-stack-protector says.
  # That comparison measures the loss of a PASS, not the difference between
  # UNKNOWN and FAIL. Check the verdicts themselves instead.
  if command -v python3 >/dev/null; then
    if "$BIN" --json "$TMP/stat" | python3 -c '
import json, sys
r = json.load(sys.stdin)["results"][0]
c = {f["id"]: f for f in r["findings"]}["canary"]
assert c["verdict"] == "unknown", c["verdict"]
assert c["confidence"].upper() == "LOW", c["confidence"]
assert r["unproven"] >= 1, r["unproven"]
' 2>/dev/null
    then ok "unprovable check reports UNKNOWN, not FAIL"
    else bad "unprovable check reports UNKNOWN, not FAIL"; fi
  fi

  # And the converse: when the evidence *is* readable, an absent canary must
  # be reported as a definite failure rather than hidden behind UNKNOWN.
  if command -v python3 >/dev/null && \
     gcc -w -O2 -fno-stack-protector -o "$TMP/nocan" "$TMP/s.c" 2>/dev/null; then
    if "$BIN" --json "$TMP/nocan" | python3 -c '
import json, sys
r = json.load(sys.stdin)["results"][0]
c = {f["id"]: f for f in r["findings"]}["canary"]
assert c["verdict"] == "fail", c["verdict"]
assert c["confidence"].upper() == "HIGH", c["confidence"]
' 2>/dev/null
    then ok "provable absence reports FAIL at HIGH confidence"
    else bad "provable absence reports FAIL at HIGH confidence"; fi
  fi

  echo "$out" | grep -q "evidence:" && ok "evidence line emitted" \
                                    || bad "evidence line emitted"
fi

echo
echo "attack surface"

if [ -f "$TMP/strong" ] && command -v readelf >/dev/null; then
  # PLT count is cross-checked against DT_PLTRELSZ rather than trusted.
  # The obvious sh_info heuristic silently returns zero on x86-64, so this
  # assertion exists specifically to catch that class of quiet wrong answer.
  mine=$("$BIN" -n --surface "$TMP/strong" 2>/dev/null \
         | grep -oE '[0-9]+ PLT entries' | grep -oE '^[0-9]+')
  truth=$(readelf -dW "$TMP/strong" 2>/dev/null \
          | awk '/PLTRELSZ/{gsub(/[^0-9]/,"",$3); print int($3/24)}')
  if [ -n "$mine" ] && [ -n "$truth" ] && [ "$mine" = "$truth" ]; then
    ok "PLT count matches DT_PLTRELSZ ($mine)"
  else
    bad "PLT count matches DT_PLTRELSZ (got '$mine', expected '$truth')"
  fi

  "$BIN" -n --surface "$TMP/strong" 2>/dev/null | grep -q "inventory, not a verdict" \
    && ok "surface is framed as inventory, not risk" \
    || bad "surface is framed as inventory, not risk"
fi

# Sensitive imports must actually be recognised, not merely counted as zero.
cat > "$TMP/sens.c" <<'SENS'
#include <stdlib.h>
#include <string.h>
int main(int c, char **v)
{
    char b[8];
    if (c > 99) { system("x"); strcpy(b, v[1]); }
    return 0;
}
SENS
if gcc -w -O0 -o "$TMP/sens" "$TMP/sens.c" 2>/dev/null; then
  out=$("$BIN" -n --surface "$TMP/sens" 2>&1)
  echo "$out" | grep -q "system"  && ok "sensitive import: system detected" \
                                  || bad "sensitive import: system detected"
  echo "$out" | grep -q "strcpy"  && ok "sensitive import: strcpy detected" \
                                  || bad "sensitive import: strcpy detected"
fi

echo
echo "reasoning and --why"

if [ -f "$TMP/cand/app" ]; then
  "$BIN" -n --reason "$TMP/cand/app" 2>&1 | grep -q "analysis" \
    && ok "reasoning section emitted" || bad "reasoning section emitted"

  # The reasoning layer must state consequences, never predict exploitability.
  # This is the guardrail that keeps the tool credible; assert it explicitly.
  if "$BIN" -n --reason "$TMP/cand/app" 2>&1 \
       | grep -qiE "is exploitable|can be exploited|guaranteed|will be compromised"
  then bad "reasoning avoids exploitability claims"
  else ok "reasoning avoids exploitability claims"; fi

  for alias in CET cet BTI ASLR ssp; do
    "$BIN" -n --why "$alias" "$TMP/cand/app" >/dev/null 2>&1 \
      && ok "--why accepts '$alias'" || bad "--why accepts '$alias'"
  done

  "$BIN" -n --why nonsense "$TMP/cand/app" >/dev/null 2>&1 \
    && bad "--why rejects an unknown check" || ok "--why rejects an unknown check"

  "$BIN" -n --why CET "$TMP/cand/app" 2>&1 | grep -q "current posture" \
    && ok "--why grounds itself in this binary" \
    || bad "--why grounds itself in this binary"
fi

echo
echo "posture diff and trend"

if [ -d "$TMP/base" ] && [ -d "$TMP/cand" ]; then
  out=$("$BIN" -n --diff "$TMP/base" "$TMP/cand" 2>&1)
  echo "$out" | grep -q "MITIGATIONS"    && ok "diff reports mitigations" \
                                         || bad "diff reports mitigations"
  echo "$out" | grep -q "ATTACK SURFACE" && ok "diff reports surface deltas" \
                                         || bad "diff reports surface deltas"
  echo "$out" | grep -q "DEGRADED"       && ok "posture verdict emitted" \
                                         || bad "posture verdict emitted"

  # Surface growth alone must not fail a build: adding a feature legitimately
  # adds exports, and a gate that fires on ordinary work gets switched off.
  mkdir -p "$TMP/g1" "$TMP/g2"
  cp "$TMP/base/app" "$TMP/g1/app"
  gcc -w -O2 -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fcf-protection=full \
      -fPIE -pie -rdynamic -Wl,-z,relro,-z,now -o "$TMP/g2/app" "$TMP/s.c" 2>/dev/null
  if [ -f "$TMP/g2/app" ]; then
    "$BIN" -n --diff "$TMP/g1" "$TMP/g2" >/dev/null 2>&1
    [ $? -eq 0 ] && ok "surface growth alone does not fail the gate" \
                 || bad "surface growth alone does not fail the gate"
  fi
fi

mkdir -p "$TMP/tr/b01" "$TMP/tr/b02" "$TMP/tr/b03"
if cp "$TMP/base/app" "$TMP/tr/b01/app" 2>/dev/null &&
   cp "$TMP/cand/app" "$TMP/tr/b02/app" 2>/dev/null &&
   cp "$TMP/base/app" "$TMP/tr/b03/app" 2>/dev/null; then
  out=$("$BIN" -n --trend "$TMP/tr" 2>&1)
  echo "$out" | grep -q "REGRESSION" && ok "trend flags the bad build" \
                                     || bad "trend flags the bad build"
  [ "$(echo "$out" | grep -cE '^  b0')" -eq 3 ] \
    && ok "trend lists every build" || bad "trend lists every build"

  mkdir -p "$TMP/tr/empty"
  [ "$("$BIN" -n --trend "$TMP/tr" 2>/dev/null | grep -cE '^  b0|^  empty')" -eq 3 ] \
    && ok "trend skips directories with no ELF" \
    || bad "trend skips directories with no ELF"
fi

echo
echo "output formats"

# These are the same validators CI runs. Keeping one implementation means a
# contributor sees the failure locally instead of on a red pipeline, and the
# two can never drift apart.
V="$ROOT/tests/validate_output.py"

if command -v python3 >/dev/null && [ -f "$TMP/cand/app" ] && [ -f "$V" ]; then
  "$BIN" --json --surface --deps --reason "$TMP/cand/app" > "$TMP/audit.json" 2>/dev/null
  "$BIN" --json --diff "$TMP/base" "$TMP/cand"            > "$TMP/diff.json"  2>/dev/null
  "$BIN" --sarif "$TMP/cand/app"                          > "$TMP/out.sarif"  2>/dev/null

  python3 "$V" audit   "$TMP/audit.json" >/dev/null 2>&1 \
    && ok "audit JSON valid and at parity with the terminal" \
    || bad "audit JSON valid and at parity with the terminal"

  python3 "$V" surface "$TMP/audit.json" >/dev/null 2>&1 \
    && ok "surface JSON complete and non-negative" \
    || bad "surface JSON complete and non-negative"

  python3 "$V" diff    "$TMP/diff.json"  >/dev/null 2>&1 \
    && ok "diff JSON self-consistent with its regression count" \
    || bad "diff JSON self-consistent with its regression count"

  python3 "$V" sarif   "$TMP/out.sarif"  >/dev/null 2>&1 \
    && ok "SARIF valid, no rule referenced without being declared" \
    || bad "SARIF valid, no rule referenced without being declared"

  if [ -d "$TMP/tr" ]; then
    "$BIN" --json --trend "$TMP/tr" > "$TMP/trend.json" 2>/dev/null
    python3 "$V" trend "$TMP/trend.json" >/dev/null 2>&1 \
      && ok "trend JSON valid" || bad "trend JSON valid"
  fi
fi

echo
echo "no colour escapes under --no-color"

for mode in "--explain --surface --deps --reason $TMP/cand/app" \
            "--diff $TMP/base $TMP/cand" \
            "--trend $TMP/tr" \
            "--why CET $TMP/cand/app"; do
  # shellcheck disable=SC2086
  n=$("$BIN" -n $mode 2>/dev/null | grep -c "$(printf '\033')")
  [ "$n" -eq 0 ] && ok "no escapes: ${mode%% *}" || bad "no escapes: ${mode%% *} ($n)"
done

echo
printf 'passed %d, failed %d\n\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
