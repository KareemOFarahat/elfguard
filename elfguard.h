/* elfguard.h — shared types for the ELF hardening auditor.
 *
 * Design note: we never expose the raw on-disk ELF structures to the rest of
 * the program. Everything is normalised into the `eg_*` structs below, so the
 * 32-bit / 64-bit and endianness split is handled in exactly one place
 * (image.c) instead of leaking into every check.
 */
#ifndef ELFGUARD_H
#define ELFGUARD_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define EG_VERSION "3.0.0"

/* ---- ELF constants we care about (redefined so we don't depend on elf.h) -- */

#define EG_ET_EXEC 2
#define EG_ET_DYN  3

#define EG_PT_LOAD          1
#define EG_PT_DYNAMIC       2
#define EG_PT_INTERP        3
#define EG_PT_NOTE          4
#define EG_PT_GNU_STACK     0x6474e551
#define EG_PT_GNU_RELRO     0x6474e552
#define EG_PT_GNU_PROPERTY  0x6474e553

#define EG_PF_X 0x1
#define EG_PF_W 0x2
#define EG_PF_R 0x4

#define EG_SHT_SYMTAB  2
#define EG_SHT_STRTAB  3
#define EG_SHT_RELA    4
#define EG_SHT_NOTE    7
#define EG_SHT_NOBITS  8
#define EG_SHT_REL     9
#define EG_SHT_DYNSYM 11

#define EG_SHF_WRITE     0x1
#define EG_SHF_ALLOC     0x2
#define EG_SHF_EXECINSTR 0x4

#define EG_SHN_UNDEF 0

#define EG_STB_GLOBAL 1
#define EG_STB_WEAK   2
#define EG_STT_OBJECT 1
#define EG_STT_FUNC   2

#define EG_DT_NULL      0
#define EG_DT_NEEDED    1
#define EG_DT_PLTRELSZ  2
#define EG_DT_STRTAB    5
#define EG_DT_RELA      7
#define EG_DT_REL      17
#define EG_DT_PLTREL   20
#define EG_DT_SONAME   14
#define EG_DT_RPATH    15
#define EG_DT_TEXTREL  22
#define EG_DT_BIND_NOW 24
#define EG_DT_RUNPATH  29
#define EG_DT_FLAGS    30
#define EG_DT_FLAGS_1  0x6ffffffb

#define EG_DF_TEXTREL    0x00000004
#define EG_DF_BIND_NOW   0x00000008
#define EG_DF_1_NOW      0x00000001
#define EG_DF_1_PIE      0x08000000

/* GNU property notes — where the modern, hardware-backed mitigations live. */
#define EG_NT_GNU_PROPERTY_TYPE_0        5
#define EG_GNU_PROPERTY_X86_FEATURE_1_AND     0xc0000002
#define EG_GNU_PROPERTY_AARCH64_FEATURE_1_AND 0xc0000000

#define EG_X86_FEATURE_1_IBT   0x1
#define EG_X86_FEATURE_1_SHSTK 0x2
#define EG_AARCH64_FEATURE_1_BTI 0x1
#define EG_AARCH64_FEATURE_1_PAC 0x2

#define EG_EM_386     0x03
#define EG_EM_X86_64  0x3e
#define EG_EM_ARM     0x28
#define EG_EM_AARCH64 0xb7

/* ---- Normalised ELF views --------------------------------------------- */

typedef struct {
    uint32_t type;    /* p_type   */
    uint32_t flags;   /* p_flags  */
    uint64_t offset;  /* p_offset */
    uint64_t vaddr;   /* p_vaddr  */
    uint64_t filesz;  /* p_filesz */
    uint64_t memsz;   /* p_memsz  */
} eg_phdr;

typedef struct {
    uint32_t name;    /* sh_name (index into shstrtab) */
    uint32_t type;    /* sh_type    */
    uint64_t flags;   /* sh_flags   */
    uint64_t addr;    /* sh_addr    */
    uint64_t offset;  /* sh_offset  */
    uint64_t size;    /* sh_size    */
    uint32_t link;    /* sh_link    */
    uint32_t info;    /* sh_info    */
    uint64_t entsize; /* sh_entsize */
} eg_shdr;

/* ---- Verdicts ---------------------------------------------------------- */

typedef enum {
    EG_OK = 0,   /* mitigation present and correctly configured */
    EG_PARTIAL,  /* present but weaker than it could be         */
    EG_BAD,      /* absent — this is an attack surface          */
    EG_UNKNOWN,  /* cannot be proven from this file             */
    EG_NA        /* does not apply to this file or architecture */
} eg_verdict;

/* How much weight the verdict above can carry.
 *
 * This distinction is the reason UNKNOWN exists as a separate state rather
 * than collapsing into FAIL. A stripped binary has not lost its stack canary;
 * it has lost our ability to see it. Reporting that as a failure produces a
 * false regression the first time someone adds `strip` to a release build,
 * and a tool that cries wolf on its own release pipeline gets switched off. */
typedef enum {
    EG_CONF_HIGH = 0,  /* direct, unambiguous evidence in the file       */
    EG_CONF_MEDIUM,    /* strong proxy, but inference is involved        */
    EG_CONF_LOW        /* the evidence needed is absent or unreadable    */
} eg_confidence;

typedef struct {
    const char   *id;      /* stable machine-readable key, e.g. "relro" */
    const char   *label;   /* human label, e.g. "RELRO"                 */
    eg_verdict    verdict;
    eg_confidence confidence;
    char          detail[128];    /* one-line summary of the verdict    */
    char          evidence[160];  /* what was actually observed         */
    char          reason[160];    /* why confidence is not HIGH         */
    const char   *impact;  /* what an attacker gains when this fails    */
} eg_finding;

/* ---- Attack-surface inventory ------------------------------------------
 *
 * Deliberately *not* an exploitability score. These are measurements: how
 * much of the binary is reachable, writable, executable, or reached through
 * an indirect branch. Surface is not vulnerability — a large surface is not
 * a bug and a small one is not safety. The number that means something is
 * the delta between two builds of the same program, which is why every field
 * here is designed to be differenced rather than graded.
 */
typedef struct {
    bool     scanned;

    size_t   exported_funcs;    /* defined FUNC symbols in .dynsym      */
    size_t   weak_symbols;      /* STB_WEAK — interposable              */
    size_t   imported_funcs;    /* UNDEF FUNC symbols                   */
    size_t   sensitive_imports; /* exec / dlopen / mprotect / unsafe str */
    char     sensitive_list[256];

    size_t   writable_globals;  /* OBJECT symbols in SHF_WRITE sections */
    size_t   exec_segments;
    size_t   writable_segments;
    uint64_t exec_bytes;
    uint64_t writable_bytes;

    size_t   plt_entries;
    size_t   indirect_calls;    /* heuristic — see surface.c            */
    size_t   indirect_jumps;
    bool     branch_scan_exact; /* true on fixed-width ISAs             */

    size_t   needed_libs;
    bool     uses_dlopen;
} eg_surface;

#define EG_MAX_FINDINGS 16
#define EG_MAX_DEPS     64
#define EG_DEP_NAME     96

typedef struct {
    char       name[EG_DEP_NAME];   /* SONAME from DT_NEEDED    */
    char       path[512];           /* resolved path, or empty  */
    bool       resolved;
    int        score;
    char       grade[3];
} eg_dep;

typedef struct {
    const char *path;
    bool        is_elf;
    char        error[192];

    /* file identity */
    int         bits;
    bool        little_endian;
    uint16_t    e_type;
    uint16_t    e_machine;
    bool        stripped;
    bool        has_interp;

    /* FORTIFY coverage: how many fortifiable libc calls actually got the
     * checked variant. A ratio says far more than a yes/no ever could. */
    size_t      fortified;
    size_t      fortifiable;

    eg_surface  surface;

    /* dependency tree (populated only with --deps) */
    eg_dep      deps[EG_MAX_DEPS];
    size_t      n_deps;
    bool        deps_scanned;
    int         weakest_dep;        /* index into deps, or -1 */

    eg_finding  findings[EG_MAX_FINDINGS];
    size_t      n_findings;

    int         score;
    char        grade[3];

    /* Security debt: what is owed, not what is scored. See debt_compute(). */
    int         debt;
    size_t      unproven;       /* checks at LOW confidence */
} eg_report;

/* Debt is deliberately a separate number from score.
 *
 * Score answers "how much of the available hardening is present". Debt adds
 * the things a score cannot express: mitigations we cannot prove, a
 * dependency weaker than the binary itself, and surface we have taken on.
 * A build can hold its score steady while its debt climbs, and that is
 * exactly the situation worth surfacing. */
int  eg_debt(const eg_report *rep);

/* Look up a finding by its stable id. Returns NULL when absent. */
const eg_finding *eg_find(const eg_report *rep, const char *id);

#endif /* ELFGUARD_H */
