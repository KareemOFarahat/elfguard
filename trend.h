/* trend.h — security posture across a series of builds. */
#ifndef ELFGUARD_TREND_H
#define ELFGUARD_TREND_H

#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>

#include "checks.h"
#include "elfguard.h"

#define EG_MAX_TREND 256

typedef struct {
    char   build[128];
    char   worst_binary[128];
    int    score;
    int    debt;
    char   grade[3];
    size_t binaries;
    size_t unproven;
    int    delta_score;
    int    delta_debt;
    bool   regression;
} eg_trend_point;

typedef struct {
    eg_trend_point points[EG_MAX_TREND];
    size_t         n;
    int            improving;   /* builds that reduced debt */
    int            degrading;   /* builds that added debt   */
    int            net_debt;    /* last debt minus first    */
    char           error[192];
} eg_trend;

/* Treat each immediate subdirectory of `root` as one build, in name order. */
bool trend_run(const char *root, eg_trend *out);

#endif /* ELFGUARD_TREND_H */
