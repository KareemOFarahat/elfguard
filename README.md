# elfguard

Audits ELF **security posture** and tracks how it changes across builds.

Most tools in this space answer *"is this binary hardened?"* — a question
nobody asks twice. elfguard answers the ones that recur:

> Is our posture getting better or worse? What changed? Where did the attack
> surface grow? And how confident are we in the result?

```
$ elfguard --diff build-v1.4/ build-v1.5/

security posture diff

REGRESSED  app  score 93 → 42 (-51)   debt 7 → 58 (+51)

  MITIGATIONS
    - PIE / ASLR                 pass → fail  ET_EXEC: image loads at a fixed base
    - RELRO                      pass → weak  Partial RELRO (no BIND_NOW)
    - Stack canary               pass → fail  no __stack_chk_fail reference
    - CET (IBT + shadow stack)   pass → fail  no .note.gnu.property CET record

  ATTACK SURFACE
    exported symbols           0 → 7     +7
    sensitive imports          0 → 2     +2
    weak symbols               0 → 1     +1
    writable globals           7 → 8     +1

SUMMARY
  4 mitigation regressions
  4 attack-surface increases
  0 dependency regressions
  0 confidence losses

  security posture: DEGRADED
```

C11, no dependencies beyond libc, ~5,000 lines including tests.

---

## The four ideas

### 1. A verdict without evidence is an assertion

Every check reports what it *saw*, not just what it concluded:

```
  [PASS]  Stack canary               __stack_chk_fail referenced
         evidence: __stack_chk_fail / __stack_chk_guard present in symbol table

  [ ?  ]  Stack canary               cannot be determined
         confidence: LOW
         evidence: no readable .symtab or .dynsym entries
         reason: symbol tables stripped — absence of the symbol is not
                 evidence of absence of the mitigation
```

**UNKNOWN is not FAIL.** This is the load-bearing rule of the whole model. A
stripped static binary cannot prove it has a stack canary, and reporting that
as a failure would be a lie about the binary and would fill every diff with
regressions nobody caused. Unprovable checks are excluded from scoring
entirely and counted separately as *unproven*.

### 2. Surface is measured, never scored

```
  attack surface (inventory, not a verdict)
    exports          0 functions, 0 weak
    imports        137 functions, 0 sensitive
    memory           1 exec segment (111 KB), 1 writable (20 KB)
                     0 writable globals
    control        135 PLT entries
                    60 indirect calls, 460 indirect jumps  (approximate)
    loading          3 linked libraries
```

There is deliberately **no exploitability score here, and there never will
be.** Surface is not vulnerability: a large exported API is a design decision,
not a bug, and a small one is not safety. Any tool that multiplies these counts
into a single "risk" number is inventing precision it does not have.

What the numbers *are* good for is subtraction. "This release exports 49
functions where the last one exported 37" is a fact about a change someone
made — checkable, attributable, and actionable in a way a risk score never is.
Every field is chosen for how well it survives being differenced.

### 3. The direction of travel beats the level

A threshold gate (`--fail-under 80`) cannot see a binary sliding from 93 to 82.
`--diff` can, and it gates on the *change*:

- **Mitigation and dependency regressions fail the build** (exit 1).
- **Surface growth is reported but does not fail it.** Adding a feature
  legitimately adds exports; a gate that fires on ordinary development gets
  switched off within a week. CI asserts this stays green.
- **A check that became unprovable is never counted as a regression.** Going
  blind is not the same as going backwards.

### 4. Consequences, not predictions

```
  analysis
    compound  PIE and control-flow integrity are both absent. Gadget addresses
              are fixed and indirect branch targets are unconstrained — the two
              properties that would each independently complicate code reuse
              are missing together.
    compound  The GOT is writable and 2 PLT entries route through it, so a
              single write primitive reaches every one of them.
```

The rules are ordinary boolean logic over verdicts already produced — a
deliberate choice. Every statement is a **consequence of a fact in the file**,
never a claim about exploitability. "PIE and CET are both absent, so code-reuse
targets are locatable and unconstrained" is checkable against the binary. "This
binary is exploitable" depends on reachable input, memory-safety bugs nobody
looked for, and the attacker's budget — none of which a static ELF reader can
see. A tool that overstates gets *all* its findings discounted, including the
true ones. The test suite asserts this boundary explicitly.

---

## Install

```sh
git clone https://github.com/KareemOFarahat/elfguard
cd elfguard
make
sudo make install      # optional → /usr/local/bin
```

Builds clean under gcc and clang with `-Wall -Wextra -Wpedantic -Wshadow
-Wconversion -Wsign-conversion -Wcast-qual -Werror`. No warnings suppressed.

## Usage

```sh
elfguard --explain ./app            # verdicts with evidence and confidence
elfguard --surface ./app            # attack-surface inventory
elfguard --deps --reason ./app      # weakest library, and what it implies
elfguard --diff old/ new/           # what changed, and in which direction
elfguard --why CET ./app            # the gap this check represents here
elfguard --trend builds/            # is debt being paid down or accrued
```

| flag | effect |
|---|---|
| `-e`, `--explain` | impact, evidence and confidence per check |
| `-u`, `--surface` | attack-surface inventory |
| `-d`, `--deps` | audit the shared libraries this binary loads |
| `-R`, `--reason` | derived consequences of the facts found |
| `-D`, `--diff A B` | mitigations, surface, confidence and dependencies |
| `-w`, `--why C F` | why one check matters given this binary's posture |
| `-t`, `--trend DIR` | score and debt across a series of builds |
| `-j` `-S` `-s` | JSON · SARIF 2.1.0 · one line per file |
| `-f N` / `-b N` | fail under score N / over debt N |

Exit: `0` clean · `1` gate tripped or regression found · `2` usage error.

`--why` accepts the vocabulary people actually have: `CET`, `IBT`, `BTI` and
`PAC` all resolve to `cfi`, `ASLR` to `pie`, `SSP` to `canary`.

---

## `--why`, grounded in the binary in front of you

```
$ elfguard --why CET ./app

why cfi matters

  CET (IBT + shadow stack): FAIL
  evidence: no GNU_PROPERTY_X86_FEATURE_1_AND record found

  current posture
    NX (non-exec stack)        PASS
    RELRO                      PASS
    PIE / ASLR                 PASS
    Stack canary               PASS
    CET (IBT + shadow stack)   FAIL

  consequence
    NX closes code injection into writable memory
               ↓
    W^X closes writing and executing the same page
               ↓
    CET would close unconstrained indirect branch targets, but is absent

  conclusion
    with the mitigations above holding, CET is the remaining gap of its
    class in this binary.
```

The chain walks the mitigations that *do* hold, so the explanation is specific
to this file rather than a paragraph that would read identically for every
binary.

## `--trend`

```
$ elfguard --trend builds/

security posture trend  (worst binary per build)

  build             score   debt  grade
  ────────────────────────────────────────
  v1.00                93      7      A
  v1.01                93      7      A
  v1.02                93      7      A
  v1.03                42     58      F   REGRESSION  (score -51, debt +51)
  v1.04                93      7      A   debt -51

  1 build reduced debt, 1 added it. Net debt over the series: +0
```

Security debt is not `100 - score`. It sums missing mitigations, dependencies
weaker than the binary itself, and checks that went unprovable — so a build can
hold a steady A while its debt climbs for six releases, every individual diff
clean and the direction unmistakable.

Builds sort by directory name, so zero-padded or date-ordered names give the
ordering you expect. That constraint is stated rather than guessed at with
version parsing that would fail silently on the first project naming things
differently.

---

## What it checks

| check | determined by | weight |
|---|---|---|
| **PIE / ASLR** | `e_type == ET_DYN` (+ `PT_INTERP` / `DF_1_PIE`) | 22 |
| **NX** | `PT_GNU_STACK` present and not `PF_X` | 18 |
| **RELRO** | `PT_GNU_RELRO`; full needs `BIND_NOW` | 18 |
| **Stack canary** | `__stack_chk_fail` in `.symtab` / `.dynsym` | 18 |
| **CET / BTI** | `.note.gnu.property` feature bits | 14 |
| **W^X** | any `PT_LOAD` both `PF_W` and `PF_X` | 10 |
| **Text relocations** | `DT_TEXTREL` / `DF_TEXTREL` | 10 |
| **FORTIFY coverage** | ratio of `__*_chk` to fortifiable calls | 8 |
| **RPATH / RUNPATH** | `DT_RPATH` / `DT_RUNPATH` | 5 |

FORTIFY is a **ratio, not a boolean** — a binary with one `__printf_chk` and
eleven raw `memcpy` calls is "fortified" by the usual measure and 8% fortified
in reality.

### Known limits

Stated plainly, because a security tool that overstates its confidence is worse
than no tool:

- **Indirect-branch counts are a linear byte scan on x86**, not a disassembly,
  so they overcount on data bytes. Marked `(approximate)` everywhere they
  appear. On AArch64, fixed-width instructions make them exact, and the output
  says which you are looking at. They are meaningful differenced against
  another build of the same code, not as absolute figures.
- **FORTIFY coverage counts referenced symbols**, not call sites.
- **`--deps` resolves one level** via standard paths and `DT_RUNPATH` with
  `$ORIGIN`. No `ld.so.cache`, no `LD_PRELOAD`. Unresolved entries are reported
  as unresolved, never silently dropped.
- **Static analysis only.** Kernel ASLR, seccomp, runtime CFI enforcement and
  `GLIBC_TUNABLES` are outside what a file on disk can show.

---

## The parser assumes the file is hostile

An ELF that elfguard scans may be malware, a fuzzer artefact, or a file crafted
to attack analysis tooling. It may declare 65,535 program headers in a 40-byte
file, or set `e_shoff` to `2^64 - 256` so a naive `off + i * size` wraps to a
small number and lands back inside the mapping.

Nothing dereferences a file-derived offset directly. Every read goes through:

```c
const void *img_at(const eg_image *img, uint64_t off, uint64_t size)
{
    uint64_t end;
    if (add_ovf(off, size, &end)) return NULL;   /* refuse wraparound */
    if (end > (uint64_t)img->len) return NULL;
    return img->base + off;
}
```

The overflow check comes **first**, deliberately: `off + size > len` is the
bug, not the fix, because the addition it relies on is the thing being
attacked.

Table walks are capped so a corrupt `p_filesz` cannot loop unbounded. Entry
sizes are validated against spec values, since a lying `e_shentsize` desyncs
every later read to an attacker-chosen stride. Strings use `memchr` bounded by
remaining mapping length. The note walker enforces both padding rules and
refuses to advance by zero. Directory walks `lstat` and skip symlinks.

### Verification

`make test` runs **75 checks** in thirteen groups — correctness, input
validation, targeted header corruption, property-note corruption, truncation
sweep, mutated corpus, diff engine, confidence model, attack surface, reasoning
and `--why`, posture diff and trend, output formats, and a check that no ANSI
escape survives `--no-color` (a log-corrupting bug this repo has already had
once).

Two of those groups assert something stronger than "does not crash":

- A corrupted note size field must never produce a **false positive**. Claiming
  CET is present when the record is malformed is worse than crashing, because
  it reports safety that is not there.
- The reasoning layer must never emit an exploitability claim. Asserted by
  pattern, so the guardrail cannot erode quietly.

`make asan` rebuilds under ASan + UBSan. Current state: 900 mutants across
every view, every truncation length, and twenty-four targeted corruptions with
zero findings. A sweep of 2,515 real system binaries and libraries across all
views produced zero crashes. That is a statement about the corpus, not a proof
— hence the libFuzzer harness on the roadmap.

Counts are cross-checked against `readelf` rather than trusted. PLT entry
counts match `DT_PLTRELSZ` exactly on curl (135), ls (104), bash (224) and
python3.12 (502) — asserted in the suite, because the obvious implementation
of that count returns zero on x86-64 and looks correct while doing it.

The JSON validators in `tests/validate_output.py` are the same ones CI runs, so
a contributor sees a failure locally rather than on a red pipeline.

### Self-audit

```
$ make check-self
  hardening score: 96/100  (A+)   security debt: 4
```

96 rather than 100: elfguard's own FORTIFY coverage is 62%, and the tool
reports that instead of flattering itself.

---

## Layout

```
include/elfguard.h   normalised structs, verdicts, confidence
include/image.h      the bounds-checking contract
src/image.c          mmap, header parsing, 32/64-bit and endianness
src/notes.c          .note.gnu.property → CET / BTI / PAC
src/surface.c        attack-surface inventory
src/checks.c         the nine checks, evidence, weights, debt
src/deps.c           DT_NEEDED resolution, weakest-link analysis
src/reason.c         rule-based consequences and --why
src/diff.c           build-to-build posture comparison
src/trend.c          debt across a series of builds
src/report.c         table / short / JSON / SARIF
src/main.c           CLI, directory walk, exit codes
```

The 32/64-bit and endianness split is confined to `image.c`; everything above
sees one normalised view, which is why adding a check is about twenty lines and
adding an architecture is zero.

## Roadmap

- Mach-O and PE backends behind the same normalised interface
- A persistent libFuzzer harness over `img_*`
- Real disassembly for exact indirect-branch counts on x86
- `ld.so.cache` parsing for exact dependency resolution

## License

MIT — see [LICENSE](LICENSE).
