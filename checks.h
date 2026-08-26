#ifndef ELFGUARD_CHECKS_H
#define ELFGUARD_CHECKS_H

#include <stdbool.h>
#include <stddef.h>

#include "elfguard.h"
#include "image.h"

/* Run every hardening check against `img` and fill `rep`. */
void checks_run(const eg_image *img, eg_report *rep);

/* Open, validate and analyse one path in a single call. */
bool eg_analyze_path(const char *path, eg_report *rep);

/* Collect DT_NEEDED sonames and the RUNPATH/RPATH search string. */
size_t eg_collect_needed(const eg_image *img, char (*names)[EG_DEP_NAME],
                         size_t max, char *searchpath, size_t splen);

#endif /* ELFGUARD_CHECKS_H */
