/* notes.c — parsing .note.gnu.property.
 *
 * This is where the mitigations that postdate the classic checksec toolset
 * live: Intel CET (IBT + shadow stack) and the AArch64 equivalents (BTI,
 * pointer authentication). They are not flags in a segment header; they are
 * announced through a nested, doubly-padded note structure that most tooling
 * never bothers to walk.
 *
 * Layout, for anyone reading this later:
 *
 *   Note header            n_namesz, n_descsz, n_type   (3 x u32)
 *   Name                   "GNU\0", padded to 4 bytes
 *   Descriptor             a *sequence* of properties, each:
 *                            pr_type    (u32)
 *                            pr_datasz  (u32)
 *                            pr_data    (pr_datasz bytes)
 *                          each property padded to 8 bytes on ELF64,
 *                          4 on ELF32
 *
 * The two padding rules differ — note names round to 4, property data rounds
 * to the class size — and getting that wrong silently desyncs the walk rather
 * than failing loudly, which is why this lives in its own file with its own
 * bounds checks rather than being inlined into checks.c.
 */
#include <string.h>

#include "notes.h"

/* Round `v` up to a multiple of `a` (a is a power of two), refusing to wrap. */
static bool align_up(uint64_t v, uint64_t a, uint64_t *out)
{
    if (a == 0) return false;
    if (v > UINT64_MAX - (a - 1)) return false;
    *out = (v + (a - 1)) & ~(a - 1);
    return true;
}

/* Walk the property array inside one NT_GNU_PROPERTY_TYPE_0 descriptor. */
static void parse_property_desc(const eg_image *img, uint64_t off, uint64_t len,
                                eg_props *out)
{
    const uint64_t palign = (img->bits == 64) ? 8 : 4;
    const uint64_t end    = off + len;
    uint64_t cur = off;

    /* Bound the iteration count independently of the length arithmetic: a
     * pr_datasz of zero would otherwise let a malformed note spin forever. */
    for (int guard = 0; guard < 256 && cur + 8 <= end; guard++) {
        uint32_t pr_type, pr_datasz;
        if (!img_u32(img, cur, &pr_type)) return;
        if (!img_u32(img, cur + 4, &pr_datasz)) return;

        const uint64_t data = cur + 8;
        if (pr_datasz > end - data) return;    /* claims more than it has */

        if (pr_type == EG_GNU_PROPERTY_X86_FEATURE_1_AND && pr_datasz >= 4) {
            uint32_t bits;
            if (img_u32(img, data, &bits)) {
                out->seen_x86 = true;
                out->ibt   = (bits & EG_X86_FEATURE_1_IBT)   != 0;
                out->shstk = (bits & EG_X86_FEATURE_1_SHSTK) != 0;
            }
        } else if (pr_type == EG_GNU_PROPERTY_AARCH64_FEATURE_1_AND &&
                   pr_datasz >= 4) {
            uint32_t bits;
            if (img_u32(img, data, &bits)) {
                out->seen_aarch64 = true;
                out->bti = (bits & EG_AARCH64_FEATURE_1_BTI) != 0;
                out->pac = (bits & EG_AARCH64_FEATURE_1_PAC) != 0;
            }
        }

        uint64_t step;
        if (!align_up(pr_datasz, palign, &step)) return;
        if (step == 0) step = palign;          /* never advance by zero */
        if (data > UINT64_MAX - step) return;
        cur = data + step;
    }
}

/* Walk a note section/segment looking for the GNU property note. */
static void parse_note_area(const eg_image *img, uint64_t off, uint64_t size,
                            eg_props *out)
{
    if (!img_at(img, off, size)) return;

    const uint64_t end = off + size;
    uint64_t cur = off;

    for (int guard = 0; guard < 256 && cur + 12 <= end; guard++) {
        uint32_t namesz, descsz, ntype;
        if (!img_u32(img, cur, &namesz) ||
            !img_u32(img, cur + 4, &descsz) ||
            !img_u32(img, cur + 8, &ntype)) return;

        uint64_t name_off = cur + 12;
        uint64_t name_pad, desc_pad;
        if (!align_up(namesz, 4, &name_pad)) return;
        if (!align_up(descsz, 4, &desc_pad)) return;
        if (name_pad > end - name_off) return;

        const uint64_t desc_off = name_off + name_pad;
        if (desc_pad > end - desc_off) return;

        /* The name is "GNU\0" — four bytes, compared against the mapping
         * through img_at rather than assumed present. */
        const char *nm = (const char *)img_at(img, name_off, namesz);
        if (nm && namesz == 4 && memcmp(nm, "GNU\0", 4) == 0 &&
            ntype == EG_NT_GNU_PROPERTY_TYPE_0) {
            parse_property_desc(img, desc_off, descsz, out);
        }

        if (desc_off > UINT64_MAX - desc_pad) return;
        cur = desc_off + desc_pad;
        if (desc_pad == 0 && name_pad == 0) return;   /* no forward progress */
    }
}

void notes_scan(const eg_image *img, eg_props *out)
{
    memset(out, 0, sizeof(*out));

    /* Prefer PT_GNU_PROPERTY: it is the segment the loader itself consults,
     * so it is the one that actually governs runtime behaviour. */
    bool found = false;
    for (uint16_t i = 0; i < img->e_phnum; i++) {
        eg_phdr ph;
        if (!img_phdr(img, i, &ph)) continue;
        if (ph.type != EG_PT_GNU_PROPERTY) continue;
        parse_note_area(img, ph.offset, ph.filesz, out);
        found = true;
    }
    if (found) return;

    /* Fall back to PT_NOTE, then to note sections — older toolchains emitted
     * the property note without a dedicated segment. */
    for (uint16_t i = 0; i < img->e_phnum; i++) {
        eg_phdr ph;
        if (!img_phdr(img, i, &ph)) continue;
        if (ph.type == EG_PT_NOTE) parse_note_area(img, ph.offset, ph.filesz, out);
    }
    if (out->seen_x86 || out->seen_aarch64) return;

    for (uint16_t i = 0; i < img->e_shnum; i++) {
        eg_shdr sh;
        if (!img_shdr(img, i, &sh)) continue;
        if (sh.type == EG_SHT_NOTE) parse_note_area(img, sh.offset, sh.size, out);
    }
}
