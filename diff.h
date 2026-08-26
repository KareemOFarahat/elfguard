/* diff.h — hardening regression detection between two builds. */
#ifndef ELFGUARD_DIFF_H
#define ELFGUARD_DIFF_H

#include <stdbool.h>
#include <stddef.h>

#include "checks.h"
#include "elfguard.h"

#define EG_MAX_DIFF    512
#define EG_MAX_CHANGES 16

typedef enum {
    EG_DIFF_SAME = 0,
    EG_DIFF_SCORE_ONLY,   /* score moved, no verdict changed */
    EG_DIFF_IMPROVED,
    EG_DIFF_REGRESSED,
    EG_DIFF_ADDED,
    EG_DIFF_REMOVED,
    EG_DIFF_UNCOMPARABLE
} eg_diff_status;

typedef struct {
    const char *id;
    const char *label;
    eg_verdict  from;
    eg_verdict  to;
    bool        is_loss;
    char        detail[128];
} eg_change;

/* A verdict that stayed put while our ability to prove it moved.
 *
 * This is its own category on purpose. Canary going PASS → UNKNOWN is not a
 * regression — nothing was removed — but it is not nothing either: the build
 * stopped being auditable. Folding it into the regression count would produce
 * a false alarm the first time someone strips a release; ignoring it entirely
 * would let a team quietly strip their way to a clean report. */
typedef struct {
    const char   *id;
    const char   *label;
    eg_confidence from;
    eg_confidence to;
} eg_conf_change;

typedef struct {
    const char *label;
    long        from;
    long        to;
    bool        approximate;   /* heuristic measure — see surface.c */
} eg_metric_delta;

#define EG_MAX_METRICS 10
#define EG_MAX_DEPDIFF 32

typedef struct {
    char name[EG_DEP_NAME];
    int  from;
    int  to;
} eg_dep_delta;

typedef struct {
    char           name[256];
    eg_diff_status status;
    int            old_score;   /* -1 when absent */
    int            new_score;
    eg_change      changes[EG_MAX_CHANGES];
    size_t         n_changes;
    size_t         regressions;
    size_t         improvements;

    eg_conf_change conf[EG_MAX_CHANGES];
    size_t         n_conf;
    size_t         confidence_losses;

    eg_metric_delta metrics[EG_MAX_METRICS];
    size_t          n_metrics;
    size_t          surface_increases;

    eg_dep_delta   deps[EG_MAX_DEPDIFF];
    size_t         n_deps;
    size_t         dep_regressions;
    int            weakest_from;
    int            weakest_to;

    int            debt_from;
    int            debt_to;
} eg_diff_entry;

/* The single-word summary a CI log gets to print. */
typedef enum {
    EG_POSTURE_IMPROVED = 0,
    EG_POSTURE_STABLE,
    EG_POSTURE_DEGRADED
} eg_posture;

typedef struct {
    eg_diff_entry entries[EG_MAX_DIFF];
    size_t        n;
    char          error[192];
} eg_diff;

bool   diff_run(const char *old_path, const char *new_path, eg_diff *out);
size_t diff_regressions(const eg_diff *d);
size_t diff_surface_increases(const eg_diff *d);
size_t diff_confidence_losses(const eg_diff *d);
size_t diff_dep_regressions(const eg_diff *d);
eg_posture diff_posture(const eg_diff *d);

#endif /* ELFGUARD_DIFF_H */
