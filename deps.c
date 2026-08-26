/* deps.c — auditing the shared libraries a binary actually loads.
 *
 * The premise: an executable's hardening score describes the executable, and
 * an executable is not what runs. What runs is the executable plus every
 * shared object the loader pulls in behind it, and an attacker gets to pick
 * which one to attack. A perfectly hardened front end that links one
 * unhardened library is as weak as that library.
 *
 * So this walks DT_NEEDED, resolves each soname the way the loader would, and
 * reports the *weakest* member of the set rather than the average — because
 * averaging is exactly the mistake that hides the problem.
 *
 * Scope, stated plainly: this resolves one level deep using the standard
 * search paths and DT_RUNPATH. It does not emulate ld.so's full algorithm —
 * no ld.so.cache, no LD_PRELOAD, no $LIB or $PLATFORM expansion — and
 * unresolved entries are reported as unresolved rather than skipped.
 */
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#include "deps.h"

/* Multiarch tuple for the usual Debian/Ubuntu layout. */
static const char *tuple_for(uint16_t machine)
{
    switch (machine) {
    case EG_EM_X86_64:  return "x86_64-linux-gnu";
    case EG_EM_386:     return "i386-linux-gnu";
    case EG_EM_AARCH64: return "aarch64-linux-gnu";
    case EG_EM_ARM:     return "arm-linux-gnueabihf";
    default:            return NULL;
    }
}

static bool is_file(const char *p)
{
    struct stat st;
    return stat(p, &st) == 0 && S_ISREG(st.st_mode);
}

/* Copy the directory part of `path` into `out`. */
static void dirname_of(const char *path, char *out, size_t outlen)
{
    const char *slash = strrchr(path, '/');
    if (!slash) { snprintf(out, outlen, "."); return; }
    size_t n = (size_t)(slash - path);
    if (n == 0) n = 1;                      /* "/lib" → "/" */
    if (n >= outlen) n = outlen - 1;
    memcpy(out, path, n);
    out[n] = '\0';
}

/* Try one directory. Returns true and fills `out` on a hit. */
static bool try_dir(const char *dir, const char *soname,
                    char *out, size_t outlen)
{
    if (!dir || !*dir) return false;
    int n = snprintf(out, outlen, "%s/%s", dir, soname);
    if (n < 0 || (size_t)n >= outlen) return false;
    return is_file(out);
}

/* Resolve `soname` against RUNPATH first (with $ORIGIN expanded), then the
 * standard directories — the same precedence the loader applies. */
static bool resolve(const char *soname, const char *runpath,
                    const char *origin, uint16_t machine,
                    char *out, size_t outlen)
{
    /* RUNPATH is a colon-separated list. */
    if (runpath && *runpath) {
        char buf[1024];
        snprintf(buf, sizeof(buf), "%s", runpath);
        for (char *tok = strtok(buf, ":"); tok; tok = strtok(NULL, ":")) {
            char expanded[768];
            if (strncmp(tok, "$ORIGIN", 7) == 0)
                snprintf(expanded, sizeof(expanded), "%s%s", origin, tok + 7);
            else if (strncmp(tok, "${ORIGIN}", 9) == 0)
                snprintf(expanded, sizeof(expanded), "%s%s", origin, tok + 9);
            else
                snprintf(expanded, sizeof(expanded), "%s", tok);
            if (try_dir(expanded, soname, out, outlen)) return true;
        }
    }

    const char *tuple = tuple_for(machine);
    if (tuple) {
        char d[256];
        snprintf(d, sizeof(d), "/lib/%s", tuple);
        if (try_dir(d, soname, out, outlen)) return true;
        snprintf(d, sizeof(d), "/usr/lib/%s", tuple);
        if (try_dir(d, soname, out, outlen)) return true;
    }

    static const char *const STD[] = {
        "/lib64", "/usr/lib64", "/lib", "/usr/lib", "/usr/local/lib",
    };
    for (size_t i = 0; i < sizeof(STD) / sizeof(STD[0]); i++)
        if (try_dir(STD[i], soname, out, outlen)) return true;

    return false;
}

void deps_scan(const char *path, eg_report *rep)
{
    rep->deps_scanned = true;
    rep->n_deps = 0;
    rep->weakest_dep = -1;

    eg_image img;
    char err[192];
    if (!img_open(&img, path, err, sizeof(err))) return;
    if (!img_parse_ehdr(&img, err, sizeof(err))) { img_close(&img); return; }

    char names[EG_MAX_DEPS][EG_DEP_NAME];
    char runpath[1024];
    const size_t n = eg_collect_needed(&img, names, EG_MAX_DEPS,
                                       runpath, sizeof(runpath));
    const uint16_t machine = img.e_machine;
    img_close(&img);

    char origin[512];
    dirname_of(path, origin, sizeof(origin));

    int worst = 101;
    for (size_t i = 0; i < n; i++) {
        eg_dep *d = &rep->deps[rep->n_deps];
        memset(d, 0, sizeof(*d));
        /* Both buffers are EG_DEP_NAME; a bounded copy plus an explicit
         * terminator is provably safe, where snprintf("%s") only looks safe
         * to a reader and not to the compiler. */
        memcpy(d->name, names[i], EG_DEP_NAME);
        d->name[EG_DEP_NAME - 1] = '\0';

        if (!resolve(d->name, runpath, origin, machine,
                     d->path, sizeof(d->path))) {
            d->resolved = false;
            snprintf(d->grade, sizeof(d->grade), "?");
            d->score = -1;
            rep->n_deps++;
            continue;
        }

        d->resolved = true;

        eg_report sub;
        if (eg_analyze_path(d->path, &sub)) {
            d->score = sub.score;
            snprintf(d->grade, sizeof(d->grade), "%s", sub.grade);
            if (sub.score < worst) {
                worst = sub.score;
                rep->weakest_dep = (int)rep->n_deps;
            }
        } else {
            d->score = -1;
            snprintf(d->grade, sizeof(d->grade), "?");
        }
        rep->n_deps++;
    }
}
