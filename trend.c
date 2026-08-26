/* trend.c — posture across a series of builds.
 *
 * `--trend builds/` treats each immediate subdirectory as one build, sorted by
 * name, and reports how score and debt moved across the series.
 *
 * The reason this is a separate view rather than a repeated diff: a single
 * diff answers "did this change break something", which teams already ask at
 * merge time. A trend answers "are we paying this down or accumulating it",
 * which nobody asks because nobody has the number in front of them. A build
 * can hold a steady A while its debt climbs for six releases — every
 * individual diff clean, the direction unmistakable.
 *
 * Sorting is by directory name, so the convention that makes this useful is
 * zero-padded or date-ordered build directories. That constraint is stated in
 * the help text rather than guessed at with version parsing, which would fail
 * silently on the first project that names things differently.
 */
#include <dirent.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#include "deps.h"
#include "trend.h"

/* Truncating copy with a length the compiler can verify.
 *
 * snprintf("%s") is safe here too, but GCC cannot prove the source is bounded
 * and warns — and a warning that has to be waved through every build is a
 * warning nobody reads. Making the bound explicit costs three lines and keeps
 * the build clean at -Werror. */
static void copy_trunc(char *dst, size_t dstsz, const char *src)
{
    size_t n = strnlen(src, dstsz - 1);
    memcpy(dst, src, n);
    dst[n] = '\0';
}

static int cmp_names(const void *a, const void *b)
{
    return strcmp((const char *)a, (const char *)b);
}

/* Score one build directory: analyse every ELF in it and keep the worst, on
 * the same weakest-link principle the dependency view uses. A release is only
 * as sound as its least hardened component. */
static bool score_build(const char *dir, eg_trend_point *pt)
{
    DIR *d = opendir(dir);
    if (!d) return false;

    int worst_score = -1, worst_debt = -1;
    size_t files = 0, unproven = 0;
    char worst_name[128] = "";

    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (ent->d_name[0] == '.') continue;

        char full[1024];
        int n = snprintf(full, sizeof(full), "%s/%s", dir, ent->d_name);
        if (n < 0 || (size_t)n >= sizeof(full)) continue;

        struct stat st;
        if (lstat(full, &st) != 0 || !S_ISREG(st.st_mode)) continue;

        eg_report rep;
        if (!eg_analyze_path(full, &rep)) continue;

        deps_scan(full, &rep);
        rep.debt = eg_debt(&rep);

        files++;
        unproven += rep.unproven;

        if (worst_score < 0 || rep.score < worst_score) {
            worst_score = rep.score;
            worst_debt  = rep.debt;
            copy_trunc(worst_name, sizeof(worst_name), ent->d_name);
        }
    }
    closedir(d);

    if (files == 0) return false;

    pt->score    = worst_score;
    pt->debt     = worst_debt;
    pt->binaries = files;
    pt->unproven = unproven;
    copy_trunc(pt->worst_binary, sizeof(pt->worst_binary), worst_name);

    const int sc = pt->score;
    const char *g = sc >= 95 ? "A+" : sc >= 85 ? "A" : sc >= 75 ? "B"
                  : sc >= 60 ? "C"  : sc >= 45 ? "D" : "F";
    snprintf(pt->grade, sizeof(pt->grade), "%s", g);
    return true;
}

bool trend_run(const char *root, eg_trend *out)
{
    memset(out, 0, sizeof(*out));

    DIR *d = opendir(root);
    if (!d) {
        snprintf(out->error, sizeof(out->error), "cannot open %s", root);
        return false;
    }

    static char names[EG_MAX_TREND][128];
    size_t n = 0;

    struct dirent *ent;
    while ((ent = readdir(d)) != NULL && n < EG_MAX_TREND) {
        if (ent->d_name[0] == '.') continue;

        char full[1024];
        int k = snprintf(full, sizeof(full), "%s/%s", root, ent->d_name);
        if (k < 0 || (size_t)k >= sizeof(full)) continue;

        struct stat st;
        if (lstat(full, &st) != 0 || !S_ISDIR(st.st_mode)) continue;

        copy_trunc(names[n], sizeof(names[n]), ent->d_name);
        n++;
    }
    closedir(d);

    if (n == 0) {
        snprintf(out->error, sizeof(out->error),
                 "no build subdirectories under %s", root);
        return false;
    }

    qsort(names, n, sizeof(names[0]), cmp_names);

    for (size_t i = 0; i < n && out->n < EG_MAX_TREND; i++) {
        char full[1024];
        int k = snprintf(full, sizeof(full), "%s/%s", root, names[i]);
        if (k < 0 || (size_t)k >= sizeof(full)) continue;

        eg_trend_point pt;
        memset(&pt, 0, sizeof(pt));
        copy_trunc(pt.build, sizeof(pt.build), names[i]);

        if (!score_build(full, &pt)) continue;

        /* Mark the regression relative to the previous *scored* build, not
         * the previous directory, so a build with no binaries in it does not
         * silently break the chain. */
        if (out->n > 0) {
            const eg_trend_point *prev = &out->points[out->n - 1];
            pt.delta_score = pt.score - prev->score;
            pt.delta_debt  = pt.debt  - prev->debt;
            pt.regression  = (pt.score < prev->score) || (pt.debt > prev->debt);
        }

        out->points[out->n++] = pt;
    }

    if (out->n == 0) {
        snprintf(out->error, sizeof(out->error),
                 "no readable ELF binaries in any build directory");
        return false;
    }

    /* Direction of travel over the whole series, which is the question the
     * view exists to answer. Comparing only first to last would miss a series
     * that recovered after a bad release, so count movements instead. */
    int up = 0, down = 0;
    for (size_t i = 1; i < out->n; i++) {
        if (out->points[i].delta_debt > 0) down++;
        else if (out->points[i].delta_debt < 0) up++;
    }
    out->improving   = up;
    out->degrading   = down;
    out->net_debt    = out->points[out->n - 1].debt - out->points[0].debt;
    return true;
}
