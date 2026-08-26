/* notes.h — GNU property note parsing (CET, BTI, PAC). */
#ifndef ELFGUARD_NOTES_H
#define ELFGUARD_NOTES_H

#include <stdbool.h>

#include "elfguard.h"
#include "image.h"

typedef struct {
    bool seen_x86;      /* an x86 feature property was present     */
    bool seen_aarch64;  /* an AArch64 feature property was present */
    bool ibt;           /* indirect branch tracking */
    bool shstk;         /* shadow stack             */
    bool bti;           /* branch target identification */
    bool pac;           /* pointer authentication       */
} eg_props;

void notes_scan(const eg_image *img, eg_props *out);

#endif /* ELFGUARD_NOTES_H */
