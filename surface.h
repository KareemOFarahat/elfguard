/* surface.h — attack-surface inventory (measurement, not scoring). */
#ifndef ELFGUARD_SURFACE_H
#define ELFGUARD_SURFACE_H

#include "checks.h"
#include "elfguard.h"
#include "image.h"

/* Populate `s` with counts describing how much of `img` is reachable,
 * writable, executable or reached indirectly. Never grades; the caller
 * decides what the numbers mean. */
void surface_scan(const eg_image *img, eg_surface *s);

#endif /* ELFGUARD_SURFACE_H */
