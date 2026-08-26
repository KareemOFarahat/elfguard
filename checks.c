/* checks.c — the actual security analysis.
 *
 * Each check answers one question: "if this mitigation is missing, what does
 * the attacker get?" That framing is deliberate. A tool that prints
 * "NX: disabled" is a lookup table. A tool that explains that a writable,
 * executable stack turns any buffer overflow into direct shellcode execution
 * is telling you why you should care.
 */
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "checks.h"
#include "notes.h"
#include "surface.h"

/* ---- finding helpers --------------------------------------------------- */

static eg_finding *add(eg_report *rep, const char *id, const char *label,
                       eg_verdict v, eg_confidence c, const char *impact)
{
    if (rep->n_findings >= EG_MAX_FINDINGS) return NULL;
    eg_finding *f = &rep->findings[rep->n_findings++];
    f->id = id;
    f->label = label;
    f->verdict = v;
    f->confidence = c;
    f->impact = impact;
    f->detail[0] = '\0';
    f->evidence[0] = '\0';
    f->reason[0] = '\0';
    if (c == EG_CONF_LOW) rep->unproven++;
    return f;
}

/* What we actually observed, in the file's own terms. Keeping this separate
 * from `detail` matters: detail is our conclusion, evidence is the input to
 * it, and a reader who disagrees with the conclusion needs the input. */
__attribute__((format(printf, 2, 3)))
static void evidence(eg_finding *f, const char *fmt, ...)
{
    if (!f) return;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(f->evidence, sizeof(f->evidence), fmt, ap);
    va_end(ap);
}

/* Why the verdict cannot be trusted at full weight. */
__attribute__((format(printf, 2, 3)))
static void reason(eg_finding *f, const char *fmt, ...)
{
    if (!f) return;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(f->reason, sizeof(f->reason), fmt, ap);
    va_end(ap);
}

__attribute__((format(printf, 2, 3)))
static void detail(eg_finding *f, const char *fmt, ...)
{
    if (!f) return;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(f->detail, sizeof(f->detail), fmt, ap);
    va_end(ap);
}

/* ---- dynamic-section walk ---------------------------------------------- */

typedef struct {
    bool     found;
    bool     bind_now;      /* DT_BIND_NOW or DF_BIND_NOW or DF_1_NOW */
    bool     textrel;       /* DT_TEXTREL or DF_TEXTREL              */
    bool     pie_flag;      /* DF_1_PIE                              */
    bool     rpath, runpath;
    uint64_t rpath_val, runpath_val;
    uint64_t strtab_vaddr;
} dyn_info;

/* Translate a virtual address to a file offset using the PT_LOAD map.
 * DT_STRTAB gives us a vaddr, but we only have the file on disk. */
static bool vaddr_to_off(const eg_image *img, uint64_t vaddr, uint64_t *off)
{
    for (uint16_t i = 0; i < img->e_phnum; i++) {
        eg_phdr ph;
        if (!img_phdr(img, i, &ph)) continue;
        if (ph.type != EG_PT_LOAD) continue;
        if (vaddr >= ph.vaddr && vaddr - ph.vaddr < ph.filesz) {
            *off = ph.offset + (vaddr - ph.vaddr);
            return true;
        }
    }
    return false;
}

static void scan_dynamic(const eg_image *img, dyn_info *d)
{
    memset(d, 0, sizeof(*d));

    eg_phdr dynph;
    bool have = false;
    for (uint16_t i = 0; i < img->e_phnum; i++) {
        eg_phdr ph;
        if (!img_phdr(img, i, &ph)) continue;
        if (ph.type == EG_PT_DYNAMIC) { dynph = ph; have = true; break; }
    }
    if (!have) return;
    d->found = true;

    const uint64_t esz = (img->bits == 64) ? 16 : 8;
    const uint64_t n   = dynph.filesz / esz;

    /* Cap the walk: a corrupt p_filesz must not turn into an unbounded loop. */
    const uint64_t limit = (n > 8192) ? 8192 : n;

    for (uint64_t i = 0; i < limit; i++) {
        const uint64_t off = dynph.offset + i * esz;
        uint64_t tag, val;

        if (img->bits == 64) {
            if (!img_u64(img, off, &tag) || !img_u64(img, off + 8, &val)) break;
        } else {
            uint32_t t32, v32;
            if (!img_u32(img, off, &t32) || !img_u32(img, off + 4, &v32)) break;
            tag = t32; val = v32;
        }

        if (tag == EG_DT_NULL) break;

        switch (tag) {
        case EG_DT_BIND_NOW: d->bind_now = true; break;
        case EG_DT_TEXTREL:  d->textrel  = true; break;
        case EG_DT_STRTAB:   d->strtab_vaddr = val; break;
        case EG_DT_RPATH:    d->rpath = true;   d->rpath_val = val;   break;
        case EG_DT_RUNPATH:  d->runpath = true; d->runpath_val = val; break;
        case EG_DT_FLAGS:
            if (val & EG_DF_BIND_NOW) d->bind_now = true;
            if (val & EG_DF_TEXTREL)  d->textrel  = true;
            break;
        case EG_DT_FLAGS_1:
            if (val & EG_DF_1_NOW) d->bind_now = true;
            if (val & EG_DF_1_PIE) d->pie_flag = true;
            break;
        default: break;
        }
    }
}

/* ---- symbol scanning ---------------------------------------------------- */

typedef struct {
    bool   stack_chk;      /* __stack_chk_fail → built with -fstack-protector */
    size_t fortify_used;   /* count of __*_chk symbols                        */
    size_t plain_used;     /* fortifiable libc calls left *unchecked*         */
    bool   has_symtab;     /* SHT_SYMTAB present → not stripped               */
    bool   saw_any;
} sym_info;

/* Functions that _FORTIFY_SOURCE can redirect to a size-checked variant.
 * Seeing `memcpy` here alongside a `__memcpy_chk` elsewhere is the signal
 * that fortification is only partial — the number that matters is the ratio,
 * not the presence of a single __*_chk symbol. */
static const char *const FORTIFIABLE[] = {
    "memcpy", "memmove", "memset", "mempcpy", "bcopy",
    "strcpy", "stpcpy", "strncpy", "strcat", "strncat",
    "sprintf", "vsprintf", "snprintf", "vsnprintf",
    "gets", "fgets", "read", "pread", "recv", "recvfrom",
    "getcwd", "realpath", "readlink", "confstr", "getwd",
    "wcscpy", "wmemcpy", "wcscat", "swprintf",
};

static bool is_fortifiable(const char *nm)
{
    for (size_t i = 0; i < sizeof(FORTIFIABLE) / sizeof(FORTIFIABLE[0]); i++)
        if (strcmp(FORTIFIABLE[i], nm) == 0) return true;
    return false;
}

static void scan_symbols(const eg_image *img, sym_info *s)
{
    memset(s, 0, sizeof(*s));

    for (uint16_t i = 0; i < img->e_shnum; i++) {
        eg_shdr sh;
        if (!img_shdr(img, i, &sh)) continue;
        if (sh.type == EG_SHT_SYMTAB) s->has_symtab = true;
        if (sh.type != EG_SHT_SYMTAB && sh.type != EG_SHT_DYNSYM) continue;

        eg_shdr strsh;
        if (sh.link >= img->e_shnum || !img_shdr(img, (uint16_t)sh.link, &strsh))
            continue;

        const uint64_t esz = sh.entsize ? sh.entsize
                                        : (img->bits == 64 ? 24 : 16);
        if (esz == 0) continue;
        uint64_t count = sh.size / esz;
        if (count > 200000) count = 200000;   /* sanity cap */

        for (uint64_t k = 0; k < count; k++) {
            uint32_t nameidx;
            if (!img_u32(img, sh.offset + k * esz, &nameidx)) break;
            if (nameidx == 0) continue;
            if (nameidx >= strsh.size) continue;

            const char *nm = img_str(img, strsh.offset + nameidx);
            if (!nm || !*nm) continue;
            s->saw_any = true;

            if (strcmp(nm, "__stack_chk_fail") == 0 ||
                strcmp(nm, "__stack_chk_guard") == 0 ||
                strcmp(nm, "__intel_security_cookie") == 0) {
                s->stack_chk = true;
            }

            /* FORTIFY_SOURCE redirects unsafe libc calls to _chk variants.
             * Count both sides so we can report coverage rather than a bare
             * yes/no. */
            const size_t len = strlen(nm);
            if (len > 6 && nm[0] == '_' && nm[1] == '_' &&
                strcmp(nm + len - 4, "_chk") == 0 &&
                strcmp(nm, "__stack_chk_fail") != 0 &&
                strcmp(nm, "__stack_chk_guard") != 0) {
                s->fortify_used++;
            } else if (is_fortifiable(nm)) {
                s->plain_used++;
            }
        }
    }
}

/* ---- individual checks -------------------------------------------------- */

static void check_nx(const eg_image *img, eg_report *rep)
{
    bool found = false;
    uint32_t flags = 0;

    for (uint16_t i = 0; i < img->e_phnum; i++) {
        eg_phdr ph;
        if (!img_phdr(img, i, &ph)) continue;
        if (ph.type == EG_PT_GNU_STACK) { found = true; flags = ph.flags; break; }
    }

    if (!found) {
        eg_finding *f = add(rep, "nx", "NX (non-exec stack)", EG_BAD,
            EG_CONF_HIGH,
            "The loader falls back to an executable stack. Any stack overflow "
            "becomes direct shellcode execution — no ROP chain needed.");
        detail(f, "no PT_GNU_STACK segment");
        evidence(f, "scanned %u program headers, no PT_GNU_STACK", img->e_phnum);
        return;
    }

    if (flags & EG_PF_X) {
        eg_finding *f = add(rep, "nx", "NX (non-exec stack)", EG_BAD,
            EG_CONF_HIGH,
            "The stack is mapped executable. Injected bytes on the stack can "
            "be jumped to and run as code.");
        detail(f, "PT_GNU_STACK is RWX");
        evidence(f, "PT_GNU_STACK p_flags = 0x%x (PF_X set)", flags);
    } else {
        eg_finding *f = add(rep, "nx", "NX (non-exec stack)", EG_OK,
            EG_CONF_HIGH,
            "Stack pages are non-executable, forcing code-reuse attacks "
            "(ROP/ret2libc) instead of plain shellcode.");
        detail(f, "PT_GNU_STACK is %s", (flags & EG_PF_W) ? "RW" : "R");
        evidence(f, "PT_GNU_STACK p_flags = 0x%x (PF_X clear)", flags);
    }
}

static void check_pie(const eg_image *img, const dyn_info *d, eg_report *rep)
{
    if (img->e_type == EG_ET_DYN) {
        const bool exe = rep->has_interp || d->pie_flag;
        eg_finding *f = add(rep, "pie", "PIE / ASLR", EG_OK, EG_CONF_HIGH,
            "The image is position-independent, so the kernel randomises its "
            "load base. Attackers must leak an address before they can build "
            "a reliable ROP chain.");
        detail(f, exe ? "ET_DYN executable (full ASLR)"
                      : "ET_DYN shared object (always relocatable)");
        evidence(f, "e_type = ET_DYN%s%s",
                 rep->has_interp ? ", PT_INTERP present" : "",
                 d->pie_flag ? ", DF_1_PIE set" : "");
        return;
    }

    eg_finding *f = add(rep, "pie", "PIE / ASLR", EG_BAD, EG_CONF_HIGH,
        "Fixed load address. Every gadget, every PLT entry and the GOT sit at "
        "addresses the attacker can hardcode — no info leak required.");
    detail(f, "ET_EXEC: image loads at a fixed base");
    evidence(f, "e_type = ET_EXEC (2)");
}

static void check_relro(const eg_image *img, const dyn_info *d, eg_report *rep)
{
    bool relro_seg = false;
    for (uint16_t i = 0; i < img->e_phnum; i++) {
        eg_phdr ph;
        if (!img_phdr(img, i, &ph)) continue;
        if (ph.type == EG_PT_GNU_RELRO) { relro_seg = true; break; }
    }

    if (!relro_seg) {
        eg_finding *f = add(rep, "relro", "RELRO", EG_BAD, EG_CONF_HIGH,
            "The GOT stays writable for the life of the process. A single "
            "arbitrary-write primitive is enough to redirect any library call "
            "to attacker-chosen code.");
        detail(f, "no PT_GNU_RELRO segment");
        evidence(f, "no PT_GNU_RELRO among %u program headers", img->e_phnum);
        return;
    }

    if (d->bind_now) {
        eg_finding *f = add(rep, "relro", "RELRO", EG_OK, EG_CONF_HIGH,
            "All relocations are resolved at load time and the GOT is then "
            "mapped read-only, closing the classic GOT-overwrite path.");
        detail(f, "Full RELRO (PT_GNU_RELRO + BIND_NOW)");
        evidence(f, "PT_GNU_RELRO present; eager binding requested");
    } else {
        eg_finding *f = add(rep, "relro", "RELRO", EG_PARTIAL, EG_CONF_HIGH,
            "Lazy binding keeps .got.plt writable, so GOT-overwrite remains "
            "available even though the rest of the RELRO region is protected.");
        detail(f, "Partial RELRO (no BIND_NOW — lazy binding)");
        evidence(f, "PT_GNU_RELRO present; no DT_BIND_NOW / DF_BIND_NOW / DF_1_NOW");
    }
}

static void check_canary(const sym_info *s, eg_report *rep)
{
    if (s->stack_chk) {
        eg_finding *f = add(rep, "canary", "Stack canary", EG_OK, EG_CONF_HIGH,
            "Guard values sit between locals and the saved return address; a "
            "linear overflow is detected before the function returns.");
        detail(f, "__stack_chk_fail referenced");
        evidence(f, "__stack_chk_fail / __stack_chk_guard present in symbol table");
        return;
    }

    /* The distinction that makes --diff trustworthy: a binary with readable
     * symbols and no canary symbol has genuinely lost the mitigation. A
     * binary with no readable symbols has lost only our view of it. Calling
     * the second one FAIL would fire a false regression the first time
     * someone adds `strip` to a release build. */
    if (s->saw_any) {
        eg_finding *f = add(rep, "canary", "Stack canary", EG_BAD, EG_CONF_HIGH,
            "Nothing validates the saved return address before it is used. A "
            "linear stack overflow overwrites control data silently.");
        detail(f, "no __stack_chk_fail reference found");
        evidence(f, "symbol table readable, no stack-protector symbol present");
        return;
    }

    eg_finding *f = add(rep, "canary", "Stack canary", EG_UNKNOWN, EG_CONF_LOW,
        "Nothing validates the saved return address before it is used. A "
        "linear stack overflow overwrites control data silently.");
    detail(f, "cannot be determined");
    evidence(f, "no readable .symtab or .dynsym entries");
    reason(f, "symbol tables stripped — absence of the symbol is not "
              "evidence of absence of the mitigation");
}

/* Reporting FORTIFY as a boolean is the single biggest source of false
 * comfort in this class of tool. A binary with one __printf_chk and eleven
 * raw memcpy calls is "fortified" by that measure and 8% fortified in
 * reality. So: report the ratio, and grade on it. */
static void check_fortify(const sym_info *s, eg_report *rep)
{
    const size_t total = s->fortify_used + s->plain_used;
    rep->fortified   = s->fortify_used;
    rep->fortifiable = total;

    if (total == 0) {
        eg_finding *f = add(rep, "fortify", "FORTIFY coverage", EG_NA,
            EG_CONF_HIGH,
            "No fortifiable libc calls are referenced, so this binary neither "
            "benefits from nor is harmed by _FORTIFY_SOURCE.");
        detail(f, "no fortifiable calls referenced");
        evidence(f, "0 fortifiable libc symbols in the symbol table");
        return;
    }

    const int pct = (int)((s->fortify_used * 100) / total);

    eg_verdict v = pct >= 80 ? EG_OK : (pct > 0 ? EG_PARTIAL : EG_BAD);
    /* MEDIUM, not HIGH: this counts referenced symbols, not call sites. A
     * single fortified call site can pull in a __*_chk symbol that then
     * "covers" for a dozen unfortified ones in another translation unit. It
     * is a strong proxy and a bad exact figure, and saying so is cheaper than
     * being caught assuming otherwise. */
    eg_finding *f = add(rep, "fortify", "FORTIFY coverage", v, EG_CONF_MEDIUM,
        "Fortifiable libc calls are compiled without size checking, so an "
        "oversized copy runs to completion instead of aborting. Coverage below "
        "100% usually means some translation units were built without "
        "-D_FORTIFY_SOURCE, or at -O0 where it has no effect.");
    detail(f, "%d%% (%zu of %zu fortifiable calls checked)",
           pct, s->fortify_used, total);
    evidence(f, "%zu __*_chk symbols vs %zu unchecked fortifiable symbols",
             s->fortify_used, s->plain_used);
    reason(f, "counts referenced symbols, not call sites");
}

/* Control-flow integrity, as announced in .note.gnu.property.
 *
 * This is the mitigation layer that arrived after the classic tooling was
 * written, and it is the one that matters most for the attacks that still
 * work: with NX and full RELRO in place, code reuse is the remaining path,
 * and IBT/BTI is what constrains it. A binary can be A-grade on every 2009
 * checkbox and still hand an attacker unconstrained indirect branches. */
static void check_cfi(const eg_image *img, const eg_props *p, eg_report *rep)
{
    if (img->e_machine == EG_EM_X86_64 || img->e_machine == EG_EM_386) {
        if (p->ibt && p->shstk) {
            eg_finding *f = add(rep, "cfi", "CET (IBT + shadow stack)", EG_OK,
                EG_CONF_HIGH,
                "Indirect branches must land on an endbr instruction and "
                "returns are validated against a shadow stack.");
            detail(f, "IBT and SHSTK both advertised");
            evidence(f, "GNU_PROPERTY_X86_FEATURE_1_AND: IBT | SHSTK");
        } else if (p->ibt || p->shstk) {
            eg_finding *f = add(rep, "cfi", "CET (IBT + shadow stack)",
                EG_PARTIAL, EG_CONF_HIGH,
                "Only half of CET is present. IBT alone leaves return-oriented "
                "chains intact; a shadow stack alone leaves indirect calls and "
                "jumps unconstrained.");
            detail(f, "%s only", p->ibt ? "IBT" : "SHSTK");
            evidence(f, "GNU_PROPERTY_X86_FEATURE_1_AND: %s",
                     p->ibt ? "IBT" : "SHSTK");
        } else {
            eg_finding *f = add(rep, "cfi", "CET (IBT + shadow stack)", EG_BAD,
                EG_CONF_HIGH,
                "Indirect branch targets are unconstrained, so any address in "
                "the image is a viable gadget entry point. With NX and RELRO "
                "in place this is the remaining path to code execution.");
            detail(f, p->seen_x86 ? "property present, no CET bits set"
                                  : "no .note.gnu.property CET record");
            evidence(f, p->seen_x86
                     ? "GNU_PROPERTY_X86_FEATURE_1_AND present, IBT and SHSTK clear"
                     : "no GNU_PROPERTY_X86_FEATURE_1_AND record found");
        }
        return;
    }

    if (img->e_machine == EG_EM_AARCH64) {
        if (p->bti && p->pac) {
            eg_finding *f = add(rep, "cfi", "BTI + PAC", EG_OK, EG_CONF_HIGH,
                "Indirect branches require a BTI landing pad and return "
                "addresses are cryptographically signed.");
            detail(f, "BTI and PAC both advertised");
            evidence(f, "GNU_PROPERTY_AARCH64_FEATURE_1_AND: BTI | PAC");
        } else if (p->bti || p->pac) {
            eg_finding *f = add(rep, "cfi", "BTI + PAC", EG_PARTIAL,
                EG_CONF_HIGH,
                "Only one of the two AArch64 control-flow protections is "
                "enabled, leaving the other class of hijack available.");
            detail(f, "%s only", p->bti ? "BTI" : "PAC");
            evidence(f, "GNU_PROPERTY_AARCH64_FEATURE_1_AND: %s",
                     p->bti ? "BTI" : "PAC");
        } else {
            eg_finding *f = add(rep, "cfi", "BTI + PAC", EG_BAD, EG_CONF_HIGH,
                "Neither branch target identification nor pointer "
                "authentication is enabled; indirect branches and return "
                "addresses are both unprotected.");
            detail(f, p->seen_aarch64 ? "property present, no CFI bits set"
                                      : "no .note.gnu.property CFI record");
            evidence(f, p->seen_aarch64
                     ? "AArch64 feature property present, BTI and PAC clear"
                     : "no GNU_PROPERTY_AARCH64_FEATURE_1_AND record found");
        }
        return;
    }

    /* Other architectures have no equivalent property record. Reporting
     * NOT_APPLICABLE rather than omitting the check keeps the finding set
     * stable across architectures, so a diff between an x86 and an ARM build
     * does not read as a mitigation appearing from nowhere. */
    eg_finding *f = add(rep, "cfi", "Control-flow integrity", EG_NA,
        EG_CONF_HIGH,
        "No control-flow integrity property is defined for this architecture.");
    detail(f, "not defined for this architecture");
    evidence(f, "e_machine = 0x%x", img->e_machine);
}

static void check_wx(const eg_image *img, eg_report *rep)
{
    int bad = 0;
    for (uint16_t i = 0; i < img->e_phnum; i++) {
        eg_phdr ph;
        if (!img_phdr(img, i, &ph)) continue;
        if (ph.type != EG_PT_LOAD) continue;
        if ((ph.flags & EG_PF_W) && (ph.flags & EG_PF_X)) bad++;
    }

    if (bad) {
        eg_finding *f = add(rep, "wx", "W^X segments", EG_BAD, EG_CONF_HIGH,
            "A segment is both writable and executable. An attacker with a "
            "write primitive can author code in place and jump to it.");
        detail(f, "%d PT_LOAD segment%s mapped RWX", bad, bad == 1 ? "" : "s");
        evidence(f, "%d of the PT_LOAD segments carry PF_W | PF_X", bad);
    } else {
        eg_finding *f = add(rep, "wx", "W^X segments", EG_OK, EG_CONF_HIGH,
            "No segment is simultaneously writable and executable.");
        detail(f, "all PT_LOAD segments respect W^X");
        evidence(f, "no PT_LOAD segment carries both PF_W and PF_X");
    }
}

static void check_rpath(const eg_image *img, const dyn_info *d, eg_report *rep)
{
    if (!d->rpath && !d->runpath) {
        eg_finding *f = add(rep, "rpath", "RPATH / RUNPATH", EG_OK,
            EG_CONF_HIGH, "No baked-in library search paths.");
        detail(f, "none set");
        evidence(f, "no DT_RPATH or DT_RUNPATH entry");
        return;
    }

    const char *val = NULL;
    uint64_t off;
    if (d->strtab_vaddr &&
        vaddr_to_off(img, d->strtab_vaddr +
                     (d->rpath ? d->rpath_val : d->runpath_val), &off))
        val = img_str(img, off);

    /* RPATH is the dangerous one: it wins over LD_LIBRARY_PATH and is not
     * overridable, so a writable directory in it is a hijack primitive. */
    const bool insecure = val && (strstr(val, "$ORIGIN") == NULL) &&
                          (val[0] != '/' || strstr(val, "/tmp") != NULL);

    eg_finding *f = add(rep, "rpath", "RPATH / RUNPATH",
        d->rpath ? (insecure ? EG_BAD : EG_PARTIAL) : EG_PARTIAL,
        val ? EG_CONF_HIGH : EG_CONF_LOW,
        "Hardcoded library search paths. If any listed directory is "
        "attacker-writable, a planted .so is loaded with the process's "
        "privileges.");
    detail(f, "%s = %.90s", d->rpath ? "RPATH" : "RUNPATH",
           val ? val : "<unreadable>");
    evidence(f, "%s entry present in .dynamic", d->rpath ? "DT_RPATH" : "DT_RUNPATH");
    if (!val)
        reason(f, "string table offset did not resolve — path contents unknown");
}

static void check_textrel(const dyn_info *d, eg_report *rep)
{
    if (!d->textrel) {
        /* Emit the clean case too. A finding that appears only on failure
         * makes every first occurrence look like an addition rather than a
         * regression, which is precisely backwards for a diff. */
        eg_finding *ok = add(rep, "textrel", "Text relocations", EG_OK,
            EG_CONF_HIGH, "No relocations against the text segment.");
        detail(ok, "none");
        evidence(ok, "no DT_TEXTREL / DF_TEXTREL entry");
        return;
    }

    eg_finding *f = add(rep, "textrel", "Text relocations", EG_BAD,
        EG_CONF_HIGH,
        "The loader must make code pages writable to apply relocations, "
        "briefly breaking W^X across the whole text segment.");
    detail(f, "DT_TEXTREL present");
    evidence(f, "DT_TEXTREL or DF_TEXTREL set in .dynamic");
}

/* ---- scoring ------------------------------------------------------------ */

static void score(eg_report *rep)
{
    /* Weights reflect exploitation reality, not a checkbox count: losing PIE
     * or RELRO hands over far more than losing FORTIFY. */
    struct { const char *id; int weight; } W[] = {
        { "nx",      18 }, { "pie",     22 }, { "relro",   18 },
        { "canary",  18 }, { "cfi",     14 }, { "fortify",  8 },
        { "wx",      10 }, { "rpath",    5 }, { "textrel", 10 },
    };

    int got = 0, total = 0;
    for (size_t i = 0; i < rep->n_findings; i++) {
        const eg_finding *f = &rep->findings[i];
        int w = 0;
        for (size_t k = 0; k < sizeof(W) / sizeof(W[0]); k++)
            if (strcmp(W[k].id, f->id) == 0) { w = W[k].weight; break; }
        /* Neither UNKNOWN nor NOT_APPLICABLE belongs in a score: one is a
         * gap in our evidence, the other a question the file cannot be asked.
         * Scoring either as a failure would penalise stripping a binary and
         * penalise building for an architecture without CET. */
        if (!w || f->verdict == EG_UNKNOWN || f->verdict == EG_NA) continue;

        total += w;
        if (f->verdict == EG_OK)           got += w;
        else if (f->verdict == EG_PARTIAL) got += w / 2;
    }

    rep->score = total ? (got * 100) / total : 0;

    const int s = rep->score;
    const char *g = s >= 95 ? "A+" : s >= 85 ? "A" : s >= 75 ? "B"
                  : s >= 60 ? "C"  : s >= 45 ? "D" : "F";
    snprintf(rep->grade, sizeof(rep->grade), "%s", g);
}

/* ---- entry point -------------------------------------------------------- */

void checks_run(const eg_image *img, eg_report *rep)
{
    rep->bits          = img->bits;
    rep->little_endian = img->little_endian;
    rep->e_type        = img->e_type;
    rep->e_machine     = img->e_machine;

    for (uint16_t i = 0; i < img->e_phnum; i++) {
        eg_phdr ph;
        if (img_phdr(img, i, &ph) && ph.type == EG_PT_INTERP) {
            rep->has_interp = true;
            break;
        }
    }

    dyn_info d;
    sym_info s;
    eg_props p;
    scan_dynamic(img, &d);
    scan_symbols(img, &s);
    notes_scan(img, &p);
    rep->stripped = !s.has_symtab;

    check_nx(img, rep);
    check_pie(img, &d, rep);
    check_relro(img, &d, rep);
    check_canary(&s, rep);
    check_fortify(&s, rep);
    check_cfi(img, &p, rep);
    check_wx(img, rep);
    check_rpath(img, &d, rep);
    check_textrel(&d, rep);

    surface_scan(img, &rep->surface);

    score(rep);
    rep->debt = eg_debt(rep);
}

/* Collect DT_NEEDED sonames plus the RUNPATH/RPATH string, so the dependency
 * resolver can search the same directories the real loader would. Reuses the
 * dynamic walker above rather than duplicating the traversal. */
size_t eg_collect_needed(const eg_image *img, char (*names)[EG_DEP_NAME],
                         size_t max, char *searchpath, size_t splen)
{
    if (splen) searchpath[0] = '\0';

    eg_phdr dynph;
    bool have = false;
    for (uint16_t i = 0; i < img->e_phnum; i++) {
        eg_phdr ph;
        if (!img_phdr(img, i, &ph)) continue;
        if (ph.type == EG_PT_DYNAMIC) { dynph = ph; have = true; break; }
    }
    if (!have) return 0;

    dyn_info d;
    scan_dynamic(img, &d);
    if (!d.strtab_vaddr) return 0;

    /* Two passes: DT_NEEDED offsets are relative to DT_STRTAB, which we can
     * only translate once the whole dynamic array has been read. */
    const uint64_t esz = (img->bits == 64) ? 16 : 8;
    const uint64_t n   = dynph.filesz / esz;
    const uint64_t lim = (n > 8192) ? 8192 : n;

    size_t count = 0;
    for (uint64_t i = 0; i < lim && count < max; i++) {
        const uint64_t off = dynph.offset + i * esz;
        uint64_t tag, val;
        if (img->bits == 64) {
            if (!img_u64(img, off, &tag) || !img_u64(img, off + 8, &val)) break;
        } else {
            uint32_t t32, v32;
            if (!img_u32(img, off, &t32) || !img_u32(img, off + 4, &v32)) break;
            tag = t32; val = v32;
        }
        if (tag == EG_DT_NULL) break;
        if (tag != EG_DT_NEEDED) continue;

        uint64_t soff;
        if (!vaddr_to_off(img, d.strtab_vaddr + val, &soff)) continue;
        const char *nm = img_str(img, soff);
        if (!nm || !*nm) continue;
        snprintf(names[count], EG_DEP_NAME, "%s", nm);
        count++;
    }

    const uint64_t rp = d.runpath ? d.runpath_val : (d.rpath ? d.rpath_val : 0);
    if (rp && splen) {
        uint64_t soff;
        if (vaddr_to_off(img, d.strtab_vaddr + rp, &soff)) {
            const char *sp = img_str(img, soff);
            if (sp) snprintf(searchpath, splen, "%s", sp);
        }
    }
    return count;
}

/* Open, validate and fully analyse one file. Returns false when the path is
 * not a readable ELF; `rep->error` explains why. */
bool eg_analyze_path(const char *path, eg_report *rep)
{
    memset(rep, 0, sizeof(*rep));
    rep->path = path;
    rep->weakest_dep = -1;

    eg_image img;
    if (!img_open(&img, path, rep->error, sizeof(rep->error))) return false;
    if (!img_parse_ehdr(&img, rep->error, sizeof(rep->error))) {
        img_close(&img);
        return false;
    }
    rep->is_elf = true;
    checks_run(&img, rep);
    img_close(&img);
    return true;
}

const eg_finding *eg_find(const eg_report *rep, const char *id)
{
    for (size_t i = 0; i < rep->n_findings; i++)
        if (strcmp(rep->findings[i].id, id) == 0) return &rep->findings[i];
    return NULL;
}

/* Security debt.
 *
 * Score answers "how much of the available hardening is present". Debt answers
 * "what do we owe", which is a different question with three extra terms:
 *
 *   1. Missing mitigation, weighted as the score already weights it.
 *   2. Checks we cannot prove. An unprovable mitigation is not a failure, but
 *      it is not free either — it is a claim nobody can audit, and it should
 *      cost something or teams will strip their way to a clean report.
 *   3. A dependency weaker than the binary. Effective posture is bounded by
 *      the weakest thing loaded, so the gap between the two is debt the
 *      binary's own score is hiding.
 *
 * Surface growth is deliberately *not* folded in here. Surface has no correct
 * absolute value, so it can only be read as a delta — it belongs in the diff,
 * not in a single-build number. Putting it here would be inventing a baseline.
 */
int eg_debt(const eg_report *rep)
{
    int debt = 100 - rep->score;

    debt += (int)rep->unproven * 3;

    if (rep->weakest_dep >= 0) {
        const int ws = rep->deps[rep->weakest_dep].score;
        if (ws >= 0 && ws < rep->score) debt += (rep->score - ws) / 2;
    }

    if (debt < 0) debt = 0;
    if (debt > 200) debt = 200;
    return debt;
}
