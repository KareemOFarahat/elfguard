/* main.c — CLI driver for elfguard. */
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "checks.h"
#include "deps.h"
#include "diff.h"
#include "image.h"
#include "reason.h"
#include "report.h"
#include "surface.h"
#include "trend.h"

typedef struct {
    eg_printer printer;
    bool       recursive;
    int        fail_under;
    int        debt_over;    /* exit 1 if security debt exceeds this */
    int        worst;
    int        max_debt;
    bool       any_elf;
} eg_ctx;

static void usage(FILE *out)
{
    fprintf(out,
"elfguard %s — audit ELF security posture and track how it changes\n"
"\n"
"USAGE\n"
"    elfguard [options] <file|directory>...\n"
"    elfguard --diff  <baseline> <candidate>\n"
"    elfguard --why   <check> <file>\n"
"    elfguard --trend <directory-of-builds>\n"
"\n"
"VIEWS\n"
"    -e, --explain        impact, evidence and confidence for each check\n"
"    -d, --deps           audit the shared libraries this binary loads\n"
"    -u, --surface        attack-surface inventory (counts, not a risk score)\n"
"    -R, --reason         derived consequences of the facts found\n"
"    -D, --diff A B       compare two builds: mitigations, surface, confidence\n"
"    -w, --why CHECK F    why one check matters given this binary's posture\n"
"    -t, --trend DIR      posture and debt across a series of builds\n"
"\n"
"OUTPUT\n"
"    -j, --json           machine-readable JSON\n"
"    -S, --sarif          SARIF 2.1.0, for GitHub code scanning\n"
"    -s, --short          one line per file (grade + score)\n"
"    -r, --recursive      walk directories\n"
"    -n, --no-color       disable ANSI colour\n"
"\n"
"GATES\n"
"    -f, --fail-under N   exit 1 if any binary scores below N\n"
"    -b, --debt-over N    exit 1 if any binary carries more debt than N\n"
"\n"
"    -h, --help           this text\n"
"    -v, --version        print version\n"
"\n"
"CHECKS\n"
"    PIE         position independence, i.e. whether ASLR applies\n"
"    NX          executable-stack flag (PT_GNU_STACK)\n"
"    RELRO       full / partial / none (GOT write protection)\n"
"    Canary      stack-protector instrumentation\n"
"    CET / BTI   IBT + shadow stack (x86), BTI + PAC (AArch64)\n"
"    FORTIFY     proportion of fortifiable libc calls actually checked\n"
"    W^X         segments mapped both writable and executable\n"
"    RPATH       hardcoded library search paths\n"
"    TEXTREL     relocations against the text segment\n"
"\n"
"    A check reports UNKNOWN when the file cannot prove it either way.\n"
"    UNKNOWN is never scored as a failure — see --explain for the reason.\n"
"\n"
"EXIT STATUS\n"
"    0  clean\n"
"    1  below a gate, or --diff found a regression\n"
"    2  usage error, or no ELF file could be read\n"
"\n"
"EXAMPLES\n"
"    elfguard --explain ./app           audit with evidence and confidence\n"
"    elfguard --surface ./app           measure the attack surface\n"
"    elfguard --deps --reason ./app     weakest link, plus what it implies\n"
"    elfguard --diff old/ new/          what changed, and in which direction\n"
"    elfguard --why CET ./app           the gap this check represents here\n"
"    elfguard --trend builds/           is debt being paid down or accrued\n"
"\n"
"NOTE ON --trend\n"
"    Builds are ordered by directory name, so zero-padded or date-ordered\n"
"    names give the ordering you expect (v1.02 sorts before v1.10).\n"
"\n", EG_VERSION);
}

static void scan_file(eg_ctx *ctx, const char *path, bool implicit)
{
    eg_report rep;

    /* `implicit` = the file came from a directory walk rather than the command
     * line. Scanning /usr/bin turns up hundreds of shell scripts; reporting
     * each as "not an ELF file" is noise the user did not ask for. When the
     * user names a file explicitly, they deserve to be told why it was
     * skipped. */
    if (!eg_analyze_path(path, &rep)) {
        rep.path = path;
        if (!implicit) report_one(&ctx->printer, stdout, &rep);
        return;
    }

    ctx->any_elf = true;
    if (ctx->printer.deps) deps_scan(path, &rep);

    if (rep.score < ctx->worst)   ctx->worst = rep.score;
    if (rep.debt  > ctx->max_debt) ctx->max_debt = rep.debt;

    /* A binary is only as strong as the weakest thing it loads, so let a weak
     * dependency drag the gate down too. Otherwise --deps would be decorative
     * in exactly the pipeline where it matters. */
    if (ctx->printer.deps && rep.weakest_dep >= 0) {
        const int ws = rep.deps[rep.weakest_dep].score;
        if (ws >= 0 && ws < ctx->worst) ctx->worst = ws;
    }

    report_one(&ctx->printer, stdout, &rep);
}

static void scan_path(eg_ctx *ctx, const char *path, int depth)
{
    struct stat st;
    if (stat(path, &st) != 0) {
        eg_report rep;
        memset(&rep, 0, sizeof(rep));
        rep.path = path;
        snprintf(rep.error, sizeof(rep.error), "cannot stat path");
        report_one(&ctx->printer, stdout, &rep);
        return;
    }

    if (!S_ISDIR(st.st_mode)) { scan_file(ctx, path, false); return; }

    if (!ctx->recursive) {
        eg_report rep;
        memset(&rep, 0, sizeof(rep));
        rep.path = path;
        snprintf(rep.error, sizeof(rep.error), "is a directory (use -r)");
        report_one(&ctx->printer, stdout, &rep);
        return;
    }

    if (depth > 32) return;

    DIR *d = opendir(path);
    if (!d) return;

    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0)
            continue;

        char child[4096];
        int n = snprintf(child, sizeof(child), "%s/%s", path, ent->d_name);
        if (n < 0 || (size_t)n >= sizeof(child)) continue;

        struct stat cst;
        if (lstat(child, &cst) != 0) continue;
        if (S_ISLNK(cst.st_mode)) continue;          /* never follow symlinks */
        if (S_ISDIR(cst.st_mode)) { scan_path(ctx, child, depth + 1); continue; }
        if (S_ISREG(cst.st_mode)) scan_file(ctx, child, true);
    }
    closedir(d);
}

int main(int argc, char **argv)
{
    eg_ctx ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.printer.mode  = EG_OUT_TABLE;
    ctx.printer.color = isatty(STDOUT_FILENO);
    ctx.fail_under    = -1;
    ctx.debt_over     = -1;
    ctx.worst         = 100;
    ctx.max_debt      = 0;

    const char *diff_a = NULL, *diff_b = NULL;
    const char *why_check = NULL, *why_file = NULL;
    const char *trend_dir = NULL;
    int first_path = 0;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];

        if (a[0] != '-' || strcmp(a, "-") == 0) { first_path = i; break; }

        if (!strcmp(a, "-h") || !strcmp(a, "--help")) { usage(stdout); return 0; }
        else if (!strcmp(a, "-v") || !strcmp(a, "--version")) {
            printf("elfguard %s\n", EG_VERSION); return 0;
        }
        else if (!strcmp(a, "-j") || !strcmp(a, "--json"))
            ctx.printer.mode = EG_OUT_JSON;
        else if (!strcmp(a, "-S") || !strcmp(a, "--sarif"))
            ctx.printer.mode = EG_OUT_SARIF;
        else if (!strcmp(a, "-s") || !strcmp(a, "--short"))
            ctx.printer.mode = EG_OUT_SHORT;
        else if (!strcmp(a, "-e") || !strcmp(a, "--explain"))
            ctx.printer.explain = true;
        else if (!strcmp(a, "-d") || !strcmp(a, "--deps"))
            ctx.printer.deps = true;
        else if (!strcmp(a, "-u") || !strcmp(a, "--surface"))
            ctx.printer.surface = true;
        else if (!strcmp(a, "-R") || !strcmp(a, "--reason"))
            ctx.printer.reason = true;
        else if (!strcmp(a, "-r") || !strcmp(a, "--recursive"))
            ctx.recursive = true;
        else if (!strcmp(a, "-n") || !strcmp(a, "--no-color"))
            ctx.printer.color = false;
        else if (!strcmp(a, "-D") || !strcmp(a, "--diff")) {
            if (i + 2 >= argc) {
                fprintf(stderr, "elfguard: --diff needs two paths\n");
                return 2;
            }
            diff_a = argv[++i];
            diff_b = argv[++i];
        }
        else if (!strcmp(a, "-w") || !strcmp(a, "--why")) {
            if (i + 2 >= argc) {
                fprintf(stderr, "elfguard: --why needs a check id and a file\n");
                return 2;
            }
            why_check = argv[++i];
            why_file  = argv[++i];
        }
        else if (!strcmp(a, "-t") || !strcmp(a, "--trend")) {
            if (i + 1 >= argc) {
                fprintf(stderr, "elfguard: --trend needs a directory\n");
                return 2;
            }
            trend_dir = argv[++i];
        }
        else if (!strcmp(a, "-f") || !strcmp(a, "--fail-under")) {
            if (i + 1 >= argc) {
                fprintf(stderr, "elfguard: --fail-under needs a value\n");
                return 2;
            }
            ctx.fail_under = atoi(argv[++i]);
        }
        else if (!strcmp(a, "-b") || !strcmp(a, "--debt-over")) {
            if (i + 1 >= argc) {
                fprintf(stderr, "elfguard: --debt-over needs a value\n");
                return 2;
            }
            ctx.debt_over = atoi(argv[++i]);
        }
        else {
            fprintf(stderr, "elfguard: unknown option '%s'\n\n", a);
            usage(stderr);
            return 2;
        }
    }

    /* Colour would corrupt any machine-readable format. */
    if (ctx.printer.mode == EG_OUT_JSON || ctx.printer.mode == EG_OUT_SARIF)
        ctx.printer.color = false;

    if (diff_a) {
        eg_diff d;
        if (!diff_run(diff_a, diff_b, &d)) {
            fprintf(stderr, "elfguard: %s\n", d.error);
            return 2;
        }
        report_diff(&ctx.printer, stdout, &d);
        /* Only a mitigation or dependency regression fails the build. Surface
         * growth is reported but does not gate: adding a feature legitimately
         * adds exports, and a gate that fires on ordinary development gets
         * disabled within a week. */
        return (diff_regressions(&d) || diff_dep_regressions(&d)) ? 1 : 0;
    }

    if (why_check) {
        eg_report rep;
        if (!eg_analyze_path(why_file, &rep)) {
            rep.path = why_file;
            fprintf(stderr, "elfguard: %s: %s\n", why_file, rep.error);
            return 2;
        }
        eg_why w;
        if (!reason_why(&rep, why_check, &w)) {
            fprintf(stderr, "elfguard: no check named '%s' in this report\n",
                    why_check);
            fprintf(stderr, "  checks: nx pie relro canary cfi fortify wx rpath textrel\n");
            fprintf(stderr, "  aliases: CET, IBT, BTI and PAC all resolve to cfi; "
                            "ASLR to pie; SSP to canary\n");
            return 2;
        }
        report_why(&ctx.printer, stdout, &rep, why_check, &w);
        return 0;
    }

    if (trend_dir) {
        eg_trend t;
        if (!trend_run(trend_dir, &t)) {
            fprintf(stderr, "elfguard: %s\n", t.error);
            return 2;
        }
        report_trend(&ctx.printer, stdout, &t);
        return 0;
    }

    if (first_path == 0) { usage(stderr); return 2; }

    report_begin(&ctx.printer, stdout);
    for (int i = first_path; i < argc; i++) scan_path(&ctx, argv[i], 0);
    report_end(&ctx.printer, stdout);

    if (!ctx.any_elf) return 2;
    if (ctx.fail_under >= 0 && ctx.worst < ctx.fail_under) return 1;
    if (ctx.debt_over  >= 0 && ctx.max_debt > ctx.debt_over) return 1;
    return 0;
}
