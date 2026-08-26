/* diff.c — comparing the hardening of two builds.
 *
 * This is the feature the tool exists for.
 *
 * A one-shot audit answers "is this binary hardened?", which is a question
 * nobody asks twice. The question teams actually have is "did we just lose
 * something?" — because hardening regressions are silent. Someone adds a
 * -O0 to debug a test failure and _FORTIFY_SOURCE quietly stops applying.
 * Someone vendors a prebuilt .so and PIE goes with it. Nothing errors, no
 * test fails, and the absolute score may still look respectable, so a
 * threshold gate sails straight past it.
 *
 * Comparing two builds catches that, and it catches it as a *direction of
 * travel* rather than a level. A binary that drops from A+ to A is far more
 * interesting than one that has been a steady C for three years.
 *
 * Directories are matched by basename, so `elfguard --diff old/ new/` does
 * the obvious thing across a whole build tree.
 */
#include <dirent.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#include "deps.h"
#include "diff.h"

static int verdict_rank(eg_verdict v)
{
    /* Higher is better. EG_UNKNOWN sits outside the ordering: a check that
     * became undeterminable is not evidence of a regression. */
    switch (v) {
    case EG_OK:      return 3;
    case EG_PARTIAL: return 2;
    case EG_BAD:     return 1;
    default:         return 0;
    }
}

static const char *basename_of(const char *p)
{
    const char *s = strrchr(p, '/');
    return s ? s + 1 : p;
}

static void add_metric(eg_diff_entry *e, const char *label,
                       size_t from, size_t to, bool approx)
{
    if (e->n_metrics >= EG_MAX_METRICS) return;
    if (from == to) return;              /* only changes are interesting */

    eg_metric_delta *m = &e->metrics[e->n_metrics++];
    m->label = label;
    m->from  = (long)from;
    m->to    = (long)to;
    m->approximate = approx;
    if (to > from) e->surface_increases++;
}

/* Surface deltas.
 *
 * Note what is compared and what is not. Absolute surface counts are close to
 * meaningless — 40 exports is neither good nor bad — but the *change* between
 * two builds of the same program is a fact about something a person did. The
 * indirect-branch figures carry an `approximate` flag because on x86 they come
 * from a byte-pattern scan; the bias is stable across builds of the same
 * program, which is exactly why it survives subtraction and would not survive
 * being reported as an absolute. */
static void diff_surface(const eg_report *a, const eg_report *b,
                         eg_diff_entry *e)
{
    const eg_surface *x = &a->surface, *y = &b->surface;
    if (!x->scanned || !y->scanned) return;

    add_metric(e, "exported symbols",   x->exported_funcs,    y->exported_funcs,    false);
    add_metric(e, "imported functions", x->imported_funcs,    y->imported_funcs,    false);
    add_metric(e, "sensitive imports",  x->sensitive_imports, y->sensitive_imports, false);
    add_metric(e, "weak symbols",       x->weak_symbols,      y->weak_symbols,      false);
    add_metric(e, "writable globals",   x->writable_globals,  y->writable_globals,  false);
    add_metric(e, "PLT entries",        x->plt_entries,       y->plt_entries,       false);

    const bool approx = !(x->branch_scan_exact && y->branch_scan_exact);
    add_metric(e, "indirect calls",     x->indirect_calls,    y->indirect_calls,    approx);
    add_metric(e, "indirect jumps",     x->indirect_jumps,    y->indirect_jumps,    approx);
    add_metric(e, "linked libraries",   x->needed_libs,       y->needed_libs,       false);
}

/* Confidence deltas — tracked separately from verdicts throughout. */
static void diff_confidence(const eg_report *a, const eg_report *b,
                            eg_diff_entry *e)
{
    for (size_t i = 0; i < b->n_findings && e->n_conf < EG_MAX_CHANGES; i++) {
        const eg_finding *nf = &b->findings[i];
        const eg_finding *of = eg_find(a, nf->id);
        if (!of || of->confidence == nf->confidence) continue;

        eg_conf_change *c = &e->conf[e->n_conf++];
        c->id    = nf->id;
        c->label = nf->label;
        c->from  = of->confidence;
        c->to    = nf->confidence;
        if (nf->confidence > of->confidence) e->confidence_losses++;
    }
}

static void diff_deps(const eg_report *a, const eg_report *b, eg_diff_entry *e)
{
    if (!a->deps_scanned || !b->deps_scanned) return;

    for (size_t i = 0; i < b->n_deps && e->n_deps < EG_MAX_DEPDIFF; i++) {
        const eg_dep *nd = &b->deps[i];
        for (size_t k = 0; k < a->n_deps; k++) {
            const eg_dep *od = &a->deps[k];
            if (strcmp(od->name, nd->name) != 0) continue;
            if (od->score == nd->score) break;

            eg_dep_delta *dd = &e->deps[e->n_deps++];
            snprintf(dd->name, sizeof(dd->name), "%s", nd->name);
            dd->from = od->score;
            dd->to   = nd->score;
            if (nd->score >= 0 && od->score >= 0 && nd->score < od->score)
                e->dep_regressions++;
            break;
        }
    }

    e->weakest_from = (a->weakest_dep >= 0) ? a->deps[a->weakest_dep].score : -1;
    e->weakest_to   = (b->weakest_dep >= 0) ? b->deps[b->weakest_dep].score : -1;
}

/* Compare one pair of reports, appending to `out`. */
static void diff_pair(const eg_report *a, const eg_report *b, eg_diff *out)
{
    if (out->n >= EG_MAX_DIFF) return;

    eg_diff_entry *e = &out->entries[out->n];
    memset(e, 0, sizeof(*e));
    snprintf(e->name, sizeof(e->name), "%s", basename_of(b->path));
    e->old_score = a->is_elf ? a->score : -1;
    e->new_score = b->is_elf ? b->score : -1;

    if (!a->is_elf || !b->is_elf) {
        e->status = EG_DIFF_UNCOMPARABLE;
        out->n++;
        return;
    }

    for (size_t i = 0; i < b->n_findings && e->n_changes < EG_MAX_CHANGES; i++) {
        const eg_finding *nf = &b->findings[i];
        const eg_finding *of = eg_find(a, nf->id);
        if (!of) continue;

        const int ro = verdict_rank(of->verdict);
        const int rn = verdict_rank(nf->verdict);
        if (ro == rn) continue;
        if (ro == 0 || rn == 0) continue;   /* unknown on either side */

        eg_change *c = &e->changes[e->n_changes++];
        c->id      = nf->id;
        c->label   = nf->label;
        c->from    = of->verdict;
        c->to      = nf->verdict;
        c->is_loss = (rn < ro);
        snprintf(c->detail, sizeof(c->detail), "%s", nf->detail);

        if (c->is_loss) e->regressions++;
        else            e->improvements++;
    }

    diff_confidence(a, b, e);
    diff_surface(a, b, e);
    diff_deps(a, b, e);

    e->debt_from = a->debt;
    e->debt_to   = b->debt;

    if (e->regressions)       e->status = EG_DIFF_REGRESSED;
    else if (e->improvements) e->status = EG_DIFF_IMPROVED;
    else if (e->old_score != e->new_score ||
             e->n_metrics || e->n_conf || e->n_deps)
                              e->status = EG_DIFF_SCORE_ONLY;
    else                      e->status = EG_DIFF_SAME;

    out->n++;
}

/* Collect regular filenames in a directory, non-recursively. */
static size_t list_dir(const char *dir, char (*names)[256], size_t max)
{
    DIR *d = opendir(dir);
    if (!d) return 0;

    size_t n = 0;
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL && n < max) {
        if (ent->d_name[0] == '.') continue;

        char full[1024];
        int k = snprintf(full, sizeof(full), "%s/%s", dir, ent->d_name);
        if (k < 0 || (size_t)k >= sizeof(full)) continue;

        struct stat st;
        if (lstat(full, &st) != 0) continue;
        if (!S_ISREG(st.st_mode)) continue;

        snprintf(names[n], 256, "%s", ent->d_name);
        n++;
    }
    closedir(d);
    return n;
}

bool diff_run(const char *old_path, const char *new_path, eg_diff *out)
{
    memset(out, 0, sizeof(*out));

    struct stat sa, sb;
    if (stat(old_path, &sa) != 0 || stat(new_path, &sb) != 0) {
        snprintf(out->error, sizeof(out->error), "cannot stat both paths");
        return false;
    }

    if (S_ISDIR(sa.st_mode) != S_ISDIR(sb.st_mode)) {
        snprintf(out->error, sizeof(out->error),
                 "cannot diff a file against a directory");
        return false;
    }

    if (!S_ISDIR(sa.st_mode)) {
        eg_report ra, rb;
        eg_analyze_path(old_path, &ra);
        eg_analyze_path(new_path, &rb);
        ra.path = old_path;
        rb.path = new_path;
        if (ra.is_elf) { deps_scan(old_path, &ra); ra.debt = eg_debt(&ra); }
        if (rb.is_elf) { deps_scan(new_path, &rb); rb.debt = eg_debt(&rb); }
        diff_pair(&ra, &rb, out);
        return true;
    }

    /* Directory mode: pair by basename. Files present on only one side are
     * reported as added/removed rather than silently dropped — a binary that
     * disappeared from a build is worth knowing about too. */
    static char anames[512][256];
    static char bnames[512][256];
    const size_t na = list_dir(old_path, anames, 512);
    const size_t nb = list_dir(new_path, bnames, 512);

    for (size_t i = 0; i < nb; i++) {
        char bp[1024];
        snprintf(bp, sizeof(bp), "%s/%s", new_path, bnames[i]);

        bool matched = false;
        for (size_t k = 0; k < na; k++) {
            if (strcmp(anames[k], bnames[i]) != 0) continue;
            matched = true;

            char ap[1024];
            snprintf(ap, sizeof(ap), "%s/%s", old_path, anames[k]);

            eg_report ra, rb;
            eg_analyze_path(ap, &ra);
            eg_analyze_path(bp, &rb);
            ra.path = ap;
            rb.path = bp;
            if (ra.is_elf) { deps_scan(ap, &ra); ra.debt = eg_debt(&ra); }
            if (rb.is_elf) { deps_scan(bp, &rb); rb.debt = eg_debt(&rb); }
            if (ra.is_elf || rb.is_elf) diff_pair(&ra, &rb, out);
            break;
        }

        if (!matched && out->n < EG_MAX_DIFF) {
            eg_report rb;
            if (eg_analyze_path(bp, &rb)) {
                eg_diff_entry *e = &out->entries[out->n++];
                memset(e, 0, sizeof(*e));
                snprintf(e->name, sizeof(e->name), "%s", bnames[i]);
                e->status    = EG_DIFF_ADDED;
                e->old_score = -1;
                e->new_score = rb.score;
            }
        }
    }

    for (size_t k = 0; k < na && out->n < EG_MAX_DIFF; k++) {
        bool matched = false;
        for (size_t i = 0; i < nb; i++)
            if (strcmp(anames[k], bnames[i]) == 0) { matched = true; break; }
        if (matched) continue;

        char ap[1024];
        snprintf(ap, sizeof(ap), "%s/%s", old_path, anames[k]);
        eg_report ra;
        if (!eg_analyze_path(ap, &ra)) continue;

        eg_diff_entry *e = &out->entries[out->n++];
        memset(e, 0, sizeof(*e));
        snprintf(e->name, sizeof(e->name), "%s", anames[k]);
        e->status    = EG_DIFF_REMOVED;
        e->old_score = ra.score;
        e->new_score = -1;
    }

    return true;
}

size_t diff_regressions(const eg_diff *d)
{
    size_t n = 0;
    for (size_t i = 0; i < d->n; i++) n += d->entries[i].regressions;
    return n;
}

size_t diff_surface_increases(const eg_diff *d)
{
    size_t n = 0;
    for (size_t i = 0; i < d->n; i++) n += d->entries[i].surface_increases;
    return n;
}

size_t diff_confidence_losses(const eg_diff *d)
{
    size_t n = 0;
    for (size_t i = 0; i < d->n; i++) n += d->entries[i].confidence_losses;
    return n;
}

size_t diff_dep_regressions(const eg_diff *d)
{
    size_t n = 0;
    for (size_t i = 0; i < d->n; i++) n += d->entries[i].dep_regressions;
    return n;
}

/* The one-word verdict.
 *
 * Only a real mitigation loss or a dependency regression can make a build
 * DEGRADED. Surface growth and confidence loss are reported prominently but
 * do not on their own flip the summary, because both have legitimate causes —
 * a feature release exports more symbols; a release build strips. Letting
 * either fail the gate by itself would train people to ignore the gate, and
 * an ignored gate protects nothing. */
eg_posture diff_posture(const eg_diff *d)
{
    if (diff_regressions(d) || diff_dep_regressions(d))
        return EG_POSTURE_DEGRADED;

    size_t gains = 0;
    for (size_t i = 0; i < d->n; i++) gains += d->entries[i].improvements;
    return gains ? EG_POSTURE_IMPROVED : EG_POSTURE_STABLE;
}
