/* deps.h — shared-library dependency auditing. */
#ifndef ELFGUARD_DEPS_H
#define ELFGUARD_DEPS_H

#include "checks.h"
#include "elfguard.h"
#include "image.h"

/* Resolve and score every DT_NEEDED entry of `path`, filling rep->deps and
 * rep->weakest_dep. Safe to call on a report that has already been analysed. */
void deps_scan(const char *path, eg_report *rep);

#endif /* ELFGUARD_DEPS_H */
