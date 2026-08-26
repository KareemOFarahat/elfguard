/* surface.c — measuring attack surface.
 *
 * A deliberate non-goal: this file does not compute an exploitability score,
 * and nothing here should ever be presented as one. Surface is not
 * vulnerability. A large exported API is a design decision, not a bug; a
 * small one is not safety. Any tool that multiplies these counts into a
 * single "risk" number is inventing precision it does not have.
 *
 * What these numbers *are* good for is differencing. "This release exports 49
 * functions where the last one exported 37" is a fact about a change someone
 * made, and it is checkable, attributable and actionable in a way that a risk
 * score never is. So every field is chosen for how well it survives being
 * subtracted from its counterpart in another build.
 */
#include <stdio.h>
#include <string.h>

#include "surface.h"

/* Imports worth naming individually: process execution, dynamic code loading,
 * memory-permission changes, and the string functions with no bound. Their
 * presence is not a finding — it is context for reading everything else. */
static const char *const SENSITIVE[] = {
    "system", "popen", "execve", "execl", "execlp", "execle",
    "execv", "execvp", "execvpe", "fexecve", "posix_spawn",
    "dlopen", "dlsym", "dlmopen",
    "mprotect", "mmap", "memfd_create",
    "gets", "strcpy", "strcat", "sprintf", "vsprintf",
    "ptrace", "setuid", "seteuid", "setgid",
};

static bool is_sensitive(const char *nm)
{
    for (size_t i = 0; i < sizeof(SENSITIVE) / sizeof(SENSITIVE[0]); i++)
        if (strcmp(SENSITIVE[i], nm) == 0) return true;
    return false;
}

/* ---- indirect branch counting -------------------------------------------
 *
 * Honest description of what this is: a byte-pattern scan, not a
 * disassembler.
 *
 * On x86-64, `FF /2` is an indirect call and `FF /4` an indirect jump, but
 * x86 instructions are variable-length and unaligned, so scanning bytes
 * linearly will match those patterns inside immediates, displacements and
 * data embedded in .text. The count is therefore an *upper bound* with a
 * consistent bias, not a true instruction count.
 *
 * That is still useful, because the bias is a property of the encoding rather
 * than of the build: the same program compiled twice mismeasures the same
 * way. Comparing two builds cancels most of it. Comparing two different
 * programs does not, which is why the report presents this figure only in
 * diffs and marks it approximate everywhere else.
 *
 * On AArch64 the situation is better: BLR and BR are single fixed-width,
 * 4-byte-aligned encodings, so the count there is exact. `branch_scan_exact`
 * records which of the two we are looking at, rather than letting the reader
 * assume.
 */
static void count_branches_x86(const uint8_t *p, size_t n, eg_surface *s)
{
    for (size_t i = 0; i + 1 < n; i++) {
        if (p[i] != 0xFF) continue;
        const uint8_t reg = (uint8_t)((p[i + 1] >> 3) & 0x7);
        if (reg == 2) s->indirect_calls++;   /* call r/m64 */
        else if (reg == 4) s->indirect_jumps++;  /* jmp r/m64 */
    }
}

static void count_branches_arm64(const eg_image *img, uint64_t off, uint64_t n,
                                 eg_surface *s)
{
    for (uint64_t i = 0; i + 4 <= n; i += 4) {
        uint32_t insn;
        if (!img_u32(img, off + i, &insn)) return;
        /* BLR Xn = 1101011000111111000000nnnnn00000
         * BR  Xn = 1101011000011111000000nnnnn00000 */
        if ((insn & 0xFFFFFC1F) == 0xD63F0000) s->indirect_calls++;
        else if ((insn & 0xFFFFFC1F) == 0xD61F0000) s->indirect_jumps++;
    }
}

/* ---- section helpers ---------------------------------------------------- */

/* Is section index `idx` writable? Used to decide whether a data symbol is a
 * writable global. Out-of-range indices answer "no" rather than reading. */
static bool section_writable(const eg_image *img, uint16_t idx)
{
    if (idx == EG_SHN_UNDEF || idx >= img->e_shnum) return false;
    eg_shdr sh;
    if (!img_shdr(img, idx, &sh)) return false;
    return (sh.flags & EG_SHF_WRITE) && (sh.flags & EG_SHF_ALLOC);
}

/* Read one symbol table entry into normalised form. */
typedef struct {
    uint32_t name;
    uint8_t  bind;
    uint8_t  type;
    uint16_t shndx;
} eg_sym;

static bool read_sym(const eg_image *img, uint64_t off, eg_sym *out)
{
    uint32_t name;
    uint8_t  info;
    uint16_t shndx;

    if (img->bits == 64) {
        const uint8_t *p = img_at(img, off + 4, 1);
        if (!img_u32(img, off, &name) || !p) return false;
        info = *p;
        if (!img_u16(img, off + 6, &shndx)) return false;
    } else {
        const uint8_t *p = img_at(img, off + 12, 1);
        if (!img_u32(img, off, &name) || !p) return false;
        info = *p;
        if (!img_u16(img, off + 14, &shndx)) return false;
    }

    out->name  = name;
    out->bind  = (uint8_t)(info >> 4);
    out->type  = (uint8_t)(info & 0xf);
    out->shndx = shndx;
    return true;
}

/* ---- inventory ---------------------------------------------------------- */

static void scan_symbols(const eg_image *img, eg_surface *s)
{
    char list[256];
    size_t used = 0;
    list[0] = '\0';

    for (uint16_t i = 0; i < img->e_shnum; i++) {
        eg_shdr sh;
        if (!img_shdr(img, i, &sh)) continue;
        if (sh.type != EG_SHT_DYNSYM && sh.type != EG_SHT_SYMTAB) continue;

        /* Prefer .dynsym: it is the externally visible interface, which is
         * what "exported" and "imported" actually mean. .symtab is only
         * consulted for writable globals, which it describes better. */
        const bool dyn = (sh.type == EG_SHT_DYNSYM);

        eg_shdr strsh;
        if (sh.link >= img->e_shnum || !img_shdr(img, (uint16_t)sh.link, &strsh))
            continue;

        const uint64_t esz = sh.entsize ? sh.entsize
                                        : (img->bits == 64 ? 24 : 16);
        if (esz == 0) continue;
        uint64_t count = sh.size / esz;
        if (count > 200000) count = 200000;

        for (uint64_t k = 0; k < count; k++) {
            eg_sym sym;
            if (!read_sym(img, sh.offset + k * esz, &sym)) break;
            if (sym.name == 0 || sym.name >= strsh.size) continue;

            const char *nm = img_str(img, strsh.offset + sym.name);
            if (!nm || !*nm) continue;

            const bool undef = (sym.shndx == EG_SHN_UNDEF);

            if (dyn) {
                if (sym.type == EG_STT_FUNC) {
                    if (undef) {
                        s->imported_funcs++;
                        if (is_sensitive(nm)) {
                            s->sensitive_imports++;
                            const size_t l = strlen(nm);
                            if (used + l + 2 < sizeof(list)) {
                                if (used) { list[used++] = ' '; }
                                memcpy(list + used, nm, l);
                                used += l;
                                list[used] = '\0';
                            }
                        }
                    } else if (sym.bind == EG_STB_GLOBAL ||
                               sym.bind == EG_STB_WEAK) {
                        s->exported_funcs++;
                    }
                }
                if (sym.bind == EG_STB_WEAK && !undef) s->weak_symbols++;
                if (!undef && strcmp(nm, "dlopen") == 0) s->uses_dlopen = true;
                if (undef && strcmp(nm, "dlopen") == 0) s->uses_dlopen = true;
            } else {
                if (sym.type == EG_STT_OBJECT && !undef &&
                    section_writable(img, sym.shndx))
                    s->writable_globals++;
            }
        }
    }

    snprintf(s->sensitive_list, sizeof(s->sensitive_list), "%s", list);
}

static void scan_segments(const eg_image *img, eg_surface *s)
{
    for (uint16_t i = 0; i < img->e_phnum; i++) {
        eg_phdr ph;
        if (!img_phdr(img, i, &ph)) continue;
        if (ph.type != EG_PT_LOAD) continue;

        if (ph.flags & EG_PF_X) { s->exec_segments++;     s->exec_bytes += ph.memsz; }
        if (ph.flags & EG_PF_W) { s->writable_segments++; s->writable_bytes += ph.memsz; }
    }
}

/* PLT entry count.
 *
 * The obvious approach — find the relocation section whose sh_info points at
 * an executable section — is wrong on x86-64, and wrong in a way that reads as
 * correct: .rela.plt's sh_info points at .got, which is writable *data*, so
 * the test silently yields zero on every ordinary binary. Dividing .plt by a
 * guessed stub size is no better, because the stub size varies (.plt.sec
 * exists only with IBT, .plt.got only for some binding modes).
 *
 * DT_PLTRELSZ is the authoritative answer: it is the byte size of the PLT
 * relocation table, stated by the linker, requiring no section names and no
 * assumption about stub layout. */
static void scan_plt_entries(const eg_image *img, eg_surface *s)
{
    eg_phdr dynph;
    bool have = false;
    for (uint16_t i = 0; i < img->e_phnum; i++) {
        eg_phdr ph;
        if (!img_phdr(img, i, &ph)) continue;
        if (ph.type == EG_PT_DYNAMIC) { dynph = ph; have = true; break; }
    }
    if (!have) return;                 /* static binary: no PLT, correctly 0 */

    const uint64_t esz = (img->bits == 64) ? 16 : 8;
    const uint64_t n   = dynph.filesz / esz;
    const uint64_t lim = (n > 8192) ? 8192 : n;

    uint64_t pltrelsz = 0, pltrel = 0;
    for (uint64_t i = 0; i < lim; i++) {
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
        if (tag == EG_DT_PLTRELSZ) pltrelsz = val;
        else if (tag == EG_DT_PLTREL) pltrel = val;
    }

    if (!pltrelsz) return;

    uint64_t relent;
    if (pltrel == EG_DT_RELA)     relent = (img->bits == 64) ? 24 : 12;
    else if (pltrel == EG_DT_REL) relent = (img->bits == 64) ? 16 : 8;
    else                          return;   /* unstated: do not guess */

    s->plt_entries = (size_t)(pltrelsz / relent);
}

static void scan_plt_and_text(const eg_image *img, eg_surface *s)
{
    for (uint16_t i = 0; i < img->e_shnum; i++) {
        eg_shdr sh;
        if (!img_shdr(img, i, &sh)) continue;

        if (sh.type == EG_SHT_NOBITS) continue;
        if (!(sh.flags & EG_SHF_EXECINSTR)) continue;
        if (sh.size == 0 || sh.size > (1u << 28)) continue;

        if (img->e_machine == EG_EM_AARCH64) {
            count_branches_arm64(img, sh.offset, sh.size, s);
            s->branch_scan_exact = true;
        } else if (img->e_machine == EG_EM_X86_64 ||
                   img->e_machine == EG_EM_386) {
            const uint8_t *p = img_at(img, sh.offset, sh.size);
            if (p) count_branches_x86(p, (size_t)sh.size, s);
            s->branch_scan_exact = false;
        }
    }
}

void surface_scan(const eg_image *img, eg_surface *s)
{
    memset(s, 0, sizeof(*s));
    s->scanned = true;

    scan_symbols(img, s);
    scan_segments(img, s);
    scan_plt_entries(img, s);
    scan_plt_and_text(img, s);

    char names[EG_MAX_DEPS][EG_DEP_NAME];
    char sp[1024];
    s->needed_libs = eg_collect_needed(img, names, EG_MAX_DEPS, sp, sizeof(sp));
}
