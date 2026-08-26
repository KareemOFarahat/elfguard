#include <string.h>

#include <stdlib.h>

#include "report.h"
#include "surface.h"

#define C_RESET "\033[0m"
#define C_DIM   "\033[2m"
#define C_BOLD  "\033[1m"
#define C_GREEN "\033[32m"
#define C_YELL  "\033[33m"
#define C_RED   "\033[31m"
#define C_GREY  "\033[90m"
#define C_CYAN  "\033[36m"

static const char *paint(const eg_printer *p, const char *c)
{
    return p->color ? c : "";
}

static const char *vcolor(eg_verdict v)
{
    switch (v) {
    case EG_OK:      return C_GREEN;
    case EG_PARTIAL: return C_YELL;
    case EG_BAD:     return C_RED;
    case EG_NA:      return C_GREY;
    default:         return C_GREY;
    }
}

static const char *vmark(eg_verdict v)
{
    switch (v) {
    case EG_OK:      return "PASS";
    case EG_PARTIAL: return "WEAK";
    case EG_BAD:     return "FAIL";
    case EG_NA:      return " -  ";
    default:         return " ?  ";
    }
}

static const char *cname(eg_confidence c)
{
    switch (c) {
    case EG_CONF_HIGH:   return "HIGH";
    case EG_CONF_MEDIUM: return "MEDIUM";
    default:             return "LOW";
    }
}

static const char *ccolor(eg_confidence c)
{
    switch (c) {
    case EG_CONF_HIGH:   return C_GREEN;
    case EG_CONF_MEDIUM: return C_YELL;
    default:             return C_GREY;
    }
}

static const char *vname(eg_verdict v)
{
    switch (v) {
    case EG_OK:      return "pass";
    case EG_PARTIAL: return "weak";
    case EG_BAD:     return "fail";
    case EG_NA:      return "not_applicable";
    default:         return "unknown";
    }
}

static const char *machine_name(uint16_t m)
{
    switch (m) {
    case 0x03: return "x86";
    case 0x28: return "ARM";
    case 0x3e: return "x86-64";
    case 0xb7: return "AArch64";
    case 0xf3: return "RISC-V";
    case 0x08: return "MIPS";
    case 0x14: return "PowerPC";
    case 0x15: return "PPC64";
    default:   return "unknown";
    }
}

static const char *type_name(uint16_t t)
{
    switch (t) {
    case 1:  return "REL";
    case 2:  return "EXEC";
    case 3:  return "DYN";
    case 4:  return "CORE";
    default: return "?";
    }
}

/* ---- JSON string escaping ---------------------------------------------- */

static void json_str(FILE *out, const char *s)
{
    fputc('"', out);
    for (; s && *s; s++) {
        unsigned char c = (unsigned char)*s;
        switch (c) {
        case '"':  fputs("\\\"", out); break;
        case '\\': fputs("\\\\", out); break;
        case '\n': fputs("\\n", out);  break;
        case '\r': fputs("\\r", out);  break;
        case '\t': fputs("\\t", out);  break;
        default:
            if (c < 0x20) fprintf(out, "\\u%04x", c);
            else          fputc(c, out);
        }
    }
    fputc('"', out);
}

/* ---- attack-surface inventory ------------------------------------------
 *
 * Presented as measurements with no verdict attached, and labelled as such.
 * The temptation to colour these red or green is exactly the mistake the
 * module exists to avoid: there is no correct number of exported symbols.
 */
static void print_surface(eg_printer *p, FILE *out, const eg_report *rep)
{
    const eg_surface *s = &rep->surface;

    fprintf(out, "\n  %sattack surface%s %s(inventory, not a verdict)%s\n",
            paint(p, C_BOLD), paint(p, C_RESET),
            paint(p, C_DIM), paint(p, C_RESET));

    fprintf(out, "    exports     %6zu functions, %zu weak\n",
            s->exported_funcs, s->weak_symbols);
    fprintf(out, "    imports     %6zu functions, %zu sensitive\n",
            s->imported_funcs, s->sensitive_imports);
    if (s->sensitive_imports)
        fprintf(out, "                %s%s%s\n",
                paint(p, C_YELL), s->sensitive_list, paint(p, C_RESET));

    fprintf(out, "    memory      %6zu exec segment%s (%llu KB), "
                 "%zu writable (%llu KB)\n",
            s->exec_segments, s->exec_segments == 1 ? "" : "s",
            (unsigned long long)(s->exec_bytes / 1024),
            s->writable_segments,
            (unsigned long long)(s->writable_bytes / 1024));
    fprintf(out, "                %6zu writable globals\n",
            s->writable_globals);

    fprintf(out, "    control     %6zu PLT entries\n", s->plt_entries);
    fprintf(out, "                %6zu indirect calls, %zu indirect jumps%s%s%s\n",
            s->indirect_calls, s->indirect_jumps,
            paint(p, C_DIM),
            s->branch_scan_exact ? "" : "  (approximate — byte scan, not disassembly)",
            paint(p, C_RESET));

    fprintf(out, "    loading     %6zu linked libraries%s\n",
            s->needed_libs, s->uses_dlopen ? ", dlopen present" : "");
}

/* ---- derived consequences ----------------------------------------------- */

static void print_reasoning(eg_printer *p, FILE *out, const eg_report *rep)
{
    eg_reasoning r;
    reason_run(rep, &r);
    if (r.n == 0) return;

    fprintf(out, "\n  %sanalysis%s\n", paint(p, C_BOLD), paint(p, C_RESET));

    for (size_t i = 0; i < r.n; i++) {
        const eg_statement *st = &r.statements[i];
        const char *kc = st->kind == EG_REASON_CLEAR   ? C_GREEN
                       : st->kind == EG_REASON_CONTEXT ? C_DIM
                       : st->kind == EG_REASON_UNPROVEN ? C_GREY : C_YELL;

        fprintf(out, "    %s%-9s%s ", paint(p, kc),
                reason_kind_name(st->kind), paint(p, C_RESET));

        /* wrap at ~64 columns under a 14-column gutter */
        const char *t = st->text;
        bool firstline = true;
        while (*t) {
            size_t n = strlen(t);
            if (n > 64) {
                n = 64;
                while (n > 0 && t[n] != ' ') n--;
                if (n == 0) n = 64;
            }
            if (!firstline) fputs("              ", out);
            fprintf(out, "%.*s\n", (int)n, t);
            firstline = false;
            t += n;
            while (*t == ' ') t++;
        }
    }
}

/* ---- table mode --------------------------------------------------------- */

static void print_table(eg_printer *p, FILE *out, const eg_report *rep)
{
    fprintf(out, "\n%s%s%s%s\n", paint(p, C_BOLD), paint(p, C_CYAN),
            rep->path, paint(p, C_RESET));

    if (!rep->is_elf) {
        fprintf(out, "  %s%s%s\n", paint(p, C_RED), rep->error, paint(p, C_RESET));
        return;
    }

    fprintf(out, "  %s%d-bit %s · %s · %s%s%s\n\n",
            paint(p, C_DIM), rep->bits, machine_name(rep->e_machine),
            type_name(rep->e_type),
            rep->stripped ? "stripped" : "symbols present",
            "", paint(p, C_RESET));

    for (size_t i = 0; i < rep->n_findings; i++) {
        const eg_finding *f = &rep->findings[i];
        fprintf(out, "  %s[%s]%s  %-26s %s%s%s\n",
                paint(p, vcolor(f->verdict)), vmark(f->verdict), paint(p, C_RESET),
                f->label,
                paint(p, C_DIM), f->detail, paint(p, C_RESET));

        /* Confidence is shown whenever it is not HIGH, and the evidence line
         * whenever the reader asked to see workings. A verdict without its
         * evidence is a thing to be believed rather than checked. */
        if (f->confidence != EG_CONF_HIGH)
            fprintf(out, "         %sconfidence: %s%s%s%s\n",
                    paint(p, C_DIM), paint(p, ccolor(f->confidence)),
                    cname(f->confidence), paint(p, C_RESET),
                    paint(p, C_RESET));

        if (p->explain && f->evidence[0])
            fprintf(out, "         %sevidence: %s%s\n",
                    paint(p, C_GREY), f->evidence, paint(p, C_RESET));

        if (f->reason[0])
            fprintf(out, "         %sreason: %s%s\n",
                    paint(p, C_GREY), f->reason, paint(p, C_RESET));

        if (p->explain && f->verdict != EG_OK && f->verdict != EG_NA && f->impact) {
            /* wrap the impact text at ~68 cols under the finding */
            const char *s = f->impact;
            while (*s) {
                size_t n = strlen(s);
                if (n > 68) {
                    n = 68;
                    while (n > 0 && s[n] != ' ') n--;
                    if (n == 0) n = 68;
                }
                fprintf(out, "         %s%s%.*s%s\n", paint(p, C_GREY),
                        paint(p, C_DIM), (int)n, s, paint(p, C_RESET));
                s += n;
                while (*s == ' ') s++;
            }
        }
    }

    const char *gc = rep->score >= 85 ? C_GREEN
                   : rep->score >= 60 ? C_YELL : C_RED;
    fprintf(out, "\n  hardening score: %s%s%d/100  (%s)%s",
            paint(p, C_BOLD), paint(p, gc), rep->score, rep->grade,
            paint(p, C_RESET));
    fprintf(out, "   %ssecurity debt: %d%s\n",
            paint(p, C_DIM), rep->debt, paint(p, C_RESET));

    if (rep->unproven)
        fprintf(out, "  %s%zu check%s could not be proven from this file%s\n",
                paint(p, C_GREY), rep->unproven,
                rep->unproven == 1 ? "" : "s", paint(p, C_RESET));

    if (p->surface && rep->surface.scanned) print_surface(p, out, rep);
    if (p->reason) print_reasoning(p, out, rep);

    if (!p->deps || !rep->deps_scanned) return;

    if (rep->n_deps == 0) {
        fprintf(out, "\n  %sno dynamic dependencies%s\n",
                paint(p, C_DIM), paint(p, C_RESET));
        return;
    }

    fprintf(out, "\n  %sdependencies (%zu)%s\n",
            paint(p, C_BOLD), rep->n_deps, paint(p, C_RESET));

    for (size_t i = 0; i < rep->n_deps; i++) {
        const eg_dep *d = &rep->deps[i];
        const bool weakest = ((int)i == rep->weakest_dep);

        if (!d->resolved) {
            fprintf(out, "    %s?  %-28s not found on the library path%s\n",
                    paint(p, C_GREY), d->name, paint(p, C_RESET));
            continue;
        }

        const char *dc = d->score >= 85 ? C_GREEN
                       : d->score >= 60 ? C_YELL : C_RED;
        fprintf(out, "    %s%-2s%s %3d  %-28s %s%s%s\n",
                paint(p, dc), d->grade, paint(p, C_RESET), d->score, d->name,
                paint(p, weakest ? C_RED : C_DIM),
                weakest ? "← weakest link" : d->path,
                paint(p, C_RESET));
    }

    if (rep->weakest_dep >= 0) {
        const eg_dep *w = &rep->deps[rep->weakest_dep];
        if (w->score < rep->score)
            fprintf(out, "\n  %seffective posture is bounded by %s at %d/100, "
                         "not by this binary at %d/100%s\n",
                    paint(p, C_YELL), w->name, w->score, rep->score,
                    paint(p, C_RESET));
    }
}

/* ---- short mode --------------------------------------------------------- */

static void print_short(eg_printer *p, FILE *out, const eg_report *rep)
{
    if (!rep->is_elf) {
        fprintf(out, "%s%-4s%s %-40s %s\n", paint(p, C_GREY), "skip",
                paint(p, C_RESET), rep->path, rep->error);
        return;
    }
    const char *gc = rep->score >= 85 ? C_GREEN
                   : rep->score >= 60 ? C_YELL : C_RED;
    fprintf(out, "%s%-2s%s %3d/100  %s\n", paint(p, gc), rep->grade,
            paint(p, C_RESET), rep->score, rep->path);
}

/* ---- JSON mode ---------------------------------------------------------- */

static void print_json(eg_printer *p, FILE *out, const eg_report *rep)
{
    if (!p->first) fputs(",\n", out);
    p->first = false;

    fputs("    {\n      \"path\": ", out);
    json_str(out, rep->path);

    if (!rep->is_elf) {
        fputs(",\n      \"elf\": false,\n      \"error\": ", out);
        json_str(out, rep->error);
        fputs("\n    }", out);
        return;
    }

    fprintf(out,
            ",\n      \"elf\": true,"
            "\n      \"bits\": %d,"
            "\n      \"arch\": \"%s\","
            "\n      \"type\": \"%s\","
            "\n      \"stripped\": %s,"
            "\n      \"fortify_checked\": %zu,"
            "\n      \"fortify_total\": %zu,"
            "\n      \"score\": %d,"
            "\n      \"grade\": \"%s\","
            "\n      \"debt\": %d,"
            "\n      \"unproven\": %zu,"
            "\n      \"findings\": [\n",
            rep->bits, machine_name(rep->e_machine), type_name(rep->e_type),
            rep->stripped ? "true" : "false",
            rep->fortified, rep->fortifiable, rep->score, rep->grade,
            rep->debt, rep->unproven);

    for (size_t i = 0; i < rep->n_findings; i++) {
        const eg_finding *f = &rep->findings[i];
        fputs("        { \"id\": ", out);
        json_str(out, f->id);
        fputs(", \"verdict\": ", out);
        json_str(out, vname(f->verdict));
        fputs(", \"detail\": ", out);
        json_str(out, f->detail);
        fputs(", \"confidence\": ", out);
        json_str(out, cname(f->confidence));
        fputs(", \"evidence\": ", out);
        json_str(out, f->evidence);
        fputs(", \"reason\": ", out);
        json_str(out, f->reason);
        fputs(", \"impact\": ", out);
        json_str(out, f->verdict == EG_OK ? "" : (f->impact ? f->impact : ""));
        fputs(" }", out);
        if (i + 1 < rep->n_findings) fputc(',', out);
        fputc('\n', out);
    }
    fputs("      ]", out);

    /* The machine format must never carry less than the terminal one — a CI
     * job consuming JSON should be able to gate on anything a human could
     * read off the table. */
    if (rep->surface.scanned) {
        const eg_surface *u = &rep->surface;
        fprintf(out,
            ",\n      \"surface\": {"
            "\n        \"exported_functions\": %zu,"
            "\n        \"weak_symbols\": %zu,"
            "\n        \"imported_functions\": %zu,"
            "\n        \"sensitive_imports\": %zu,"
            "\n        \"writable_globals\": %zu,"
            "\n        \"exec_segments\": %zu,"
            "\n        \"writable_segments\": %zu,"
            "\n        \"exec_bytes\": %llu,"
            "\n        \"writable_bytes\": %llu,"
            "\n        \"plt_entries\": %zu,"
            "\n        \"indirect_calls\": %zu,"
            "\n        \"indirect_jumps\": %zu,"
            "\n        \"branch_counts_exact\": %s,"
            "\n        \"needed_libraries\": %zu,"
            "\n        \"uses_dlopen\": %s,"
            "\n        \"sensitive_list\": ",
            u->exported_funcs, u->weak_symbols, u->imported_funcs,
            u->sensitive_imports, u->writable_globals,
            u->exec_segments, u->writable_segments,
            (unsigned long long)u->exec_bytes,
            (unsigned long long)u->writable_bytes,
            u->plt_entries, u->indirect_calls, u->indirect_jumps,
            u->branch_scan_exact ? "true" : "false",
            u->needed_libs, u->uses_dlopen ? "true" : "false");
        json_str(out, u->sensitive_list);
        fputs("\n      }", out);
    }

    if (p->reason) {
        eg_reasoning rr;
        reason_run(rep, &rr);
        fputs(",\n      \"reasoning\": [\n", out);
        for (size_t i = 0; i < rr.n; i++) {
            fputs("        { \"kind\": ", out);
            json_str(out, reason_kind_name(rr.statements[i].kind));
            fputs(", \"text\": ", out);
            json_str(out, rr.statements[i].text);
            fputs(", \"derived_from\": ", out);
            json_str(out, rr.statements[i].derived_from);
            fputs(" }", out);
            if (i + 1 < rr.n) fputc(',', out);
            fputc('\n', out);
        }
        fputs("      ]", out);
    }

    if (rep->deps_scanned) {
        fputs(",\n      \"dependencies\": [\n", out);
        for (size_t i = 0; i < rep->n_deps; i++) {
            const eg_dep *d = &rep->deps[i];
            fputs("        { \"name\": ", out);
            json_str(out, d->name);
            fputs(", \"resolved\": ", out);
            fputs(d->resolved ? "true" : "false", out);
            if (d->resolved) {
                fputs(", \"path\": ", out);
                json_str(out, d->path);
                fprintf(out, ", \"score\": %d, \"grade\": \"%s\"",
                        d->score, d->grade);
            }
            fprintf(out, ", \"weakest\": %s }",
                    ((int)i == rep->weakest_dep) ? "true" : "false");
            if (i + 1 < rep->n_deps) fputc(',', out);
            fputc('\n', out);
        }
        fputs("      ]", out);
    }

    fputs("\n    }", out);
}

/* ---- SARIF ---------------------------------------------------------------
 *
 * SARIF is what turns this from a terminal tool into something that annotates
 * a pull request. GitHub's code-scanning ingests it directly, so a missing
 * mitigation shows up as a review comment on the line of the build config
 * that caused it — which is where the person who can fix it is looking.
 */

static const char *sarif_level(eg_verdict v)
{
    switch (v) {
    case EG_BAD:     return "error";
    case EG_PARTIAL: return "warning";
    default:         return "note";
    }
}

static void sarif_rule(FILE *out, const eg_finding *f, bool comma)
{
    fputs("          { \"id\": ", out);
    json_str(out, f->id);
    fputs(", \"name\": ", out);
    json_str(out, f->label);
    fputs(", \"shortDescription\": { \"text\": ", out);
    json_str(out, f->label);
    fputs(" }, \"fullDescription\": { \"text\": ", out);
    json_str(out, f->impact ? f->impact : "");
    fputs(" } }", out);
    if (comma) fputc(',', out);
    fputc('\n', out);
}

static void print_sarif(eg_printer *p, FILE *out, const eg_report *rep)
{
    if (!rep->is_elf) return;

    for (size_t i = 0; i < rep->n_findings; i++) {
        const eg_finding *f = &rep->findings[i];
        if (f->verdict == EG_OK || f->verdict == EG_UNKNOWN) continue;

        if (!p->first) fputs(",\n", out);
        p->first = false;

        fputs("        { \"ruleId\": ", out);
        json_str(out, f->id);
        fprintf(out, ", \"level\": \"%s\", \"message\": { \"text\": ",
                sarif_level(f->verdict));

        char msg[512];
        snprintf(msg, sizeof(msg), "%s: %s. %s",
                 f->label, f->detail, f->impact ? f->impact : "");
        json_str(out, msg);

        fputs(" }, \"locations\": [ { \"physicalLocation\": "
              "{ \"artifactLocation\": { \"uri\": ", out);
        json_str(out, rep->path);
        fputs(" } } } ] }", out);
    }
}

/* ---- diff rendering ------------------------------------------------------ */

static const char *posture_name(eg_posture p)
{
    switch (p) {
    case EG_POSTURE_IMPROVED: return "IMPROVED";
    case EG_POSTURE_DEGRADED: return "DEGRADED";
    default:                  return "STABLE";
    }
}

void report_diff(eg_printer *p, FILE *out, const eg_diff *d)
{
    const size_t regs    = diff_regressions(d);
    const size_t surf    = diff_surface_increases(d);
    const size_t confl   = diff_confidence_losses(d);
    const size_t depregs = diff_dep_regressions(d);
    const eg_posture post = diff_posture(d);

    if (p->mode == EG_OUT_JSON) {
        fprintf(out, "{\n  \"tool\": \"elfguard\",\n  \"version\": \"%s\",\n"
                     "  \"mode\": \"diff\",\n"
                     "  \"posture\": \"%s\",\n"
                     "  \"regressions\": %zu,\n"
                     "  \"surface_increases\": %zu,\n"
                     "  \"confidence_losses\": %zu,\n"
                     "  \"dependency_regressions\": %zu,\n"
                     "  \"entries\": [\n",
                EG_VERSION, posture_name(post), regs, surf, confl, depregs);

        for (size_t i = 0; i < d->n; i++) {
            const eg_diff_entry *e = &d->entries[i];
            fputs("    { \"name\": ", out);
            json_str(out, e->name);
            fprintf(out, ", \"old_score\": %d, \"new_score\": %d, "
                         "\"old_debt\": %d, \"new_debt\": %d, "
                         "\"regressions\": %zu, \"improvements\": %zu",
                    e->old_score, e->new_score, e->debt_from, e->debt_to,
                    e->regressions, e->improvements);

            fputs(", \"mitigations\": [", out);
            for (size_t k = 0; k < e->n_changes; k++) {
                const eg_change *c = &e->changes[k];
                fputs(k ? ", { \"id\": " : " { \"id\": ", out);
                json_str(out, c->id);
                fprintf(out, ", \"from\": \"%s\", \"to\": \"%s\", "
                             "\"regression\": %s }",
                        vname(c->from), vname(c->to),
                        c->is_loss ? "true" : "false");
            }
            fputs(" ]", out);

            fputs(", \"surface\": [", out);
            for (size_t k = 0; k < e->n_metrics; k++) {
                const eg_metric_delta *m = &e->metrics[k];
                fputs(k ? ", { \"metric\": " : " { \"metric\": ", out);
                json_str(out, m->label);
                fprintf(out, ", \"from\": %ld, \"to\": %ld, "
                             "\"delta\": %ld, \"approximate\": %s }",
                        m->from, m->to, m->to - m->from,
                        m->approximate ? "true" : "false");
            }
            fputs(" ]", out);

            fputs(", \"confidence\": [", out);
            for (size_t k = 0; k < e->n_conf; k++) {
                const eg_conf_change *c = &e->conf[k];
                fputs(k ? ", { \"id\": " : " { \"id\": ", out);
                json_str(out, c->id);
                fprintf(out, ", \"from\": \"%s\", \"to\": \"%s\" }",
                        cname(c->from), cname(c->to));
            }
            fputs(" ]", out);

            fputs(", \"dependencies\": [", out);
            for (size_t k = 0; k < e->n_deps; k++) {
                const eg_dep_delta *dd = &e->deps[k];
                fputs(k ? ", { \"name\": " : " { \"name\": ", out);
                json_str(out, dd->name);
                fprintf(out, ", \"from\": %d, \"to\": %d }", dd->from, dd->to);
            }
            fputs(" ] }", out);

            if (i + 1 < d->n) fputc(',', out);
            fputc('\n', out);
        }
        fputs("  ]\n}\n", out);
        return;
    }

    fprintf(out, "\n%ssecurity posture diff%s\n",
            paint(p, C_BOLD), paint(p, C_RESET));

    bool any = false;
    for (size_t i = 0; i < d->n; i++) {
        const eg_diff_entry *e = &d->entries[i];
        if (e->status == EG_DIFF_SAME) continue;
        any = true;

        const char *tag, *tc;
        switch (e->status) {
        case EG_DIFF_REGRESSED:  tag = "REGRESSED"; tc = C_RED;   break;
        case EG_DIFF_IMPROVED:   tag = "IMPROVED";  tc = C_GREEN; break;
        case EG_DIFF_ADDED:      tag = "ADDED";     tc = C_CYAN;  break;
        case EG_DIFF_REMOVED:    tag = "REMOVED";   tc = C_GREY;  break;
        case EG_DIFF_SCORE_ONLY: tag = "CHANGED";   tc = C_YELL;  break;
        default:                 tag = "n/a";       tc = C_GREY;  break;
        }

        fprintf(out, "\n%s%s%s  %s", paint(p, tc), tag, paint(p, C_RESET),
                e->name);
        if (e->old_score >= 0 && e->new_score >= 0)
            fprintf(out, "  %sscore %d → %d (%+d)   debt %d → %d (%+d)%s",
                    paint(p, C_DIM), e->old_score, e->new_score,
                    e->new_score - e->old_score,
                    e->debt_from, e->debt_to, e->debt_to - e->debt_from,
                    paint(p, C_RESET));
        fputc('\n', out);

        if (e->n_changes) {
            fprintf(out, "\n  %sMITIGATIONS%s\n",
                    paint(p, C_BOLD), paint(p, C_RESET));
            for (size_t k = 0; k < e->n_changes; k++) {
                const eg_change *c = &e->changes[k];
                fprintf(out, "    %s%s%s %-26s %s → %s  %s%s%s\n",
                        paint(p, c->is_loss ? C_RED : C_GREEN),
                        c->is_loss ? "-" : "+", paint(p, C_RESET),
                        c->label, vname(c->from), vname(c->to),
                        paint(p, C_DIM), c->detail, paint(p, C_RESET));
            }
        }

        if (e->n_metrics) {
            fprintf(out, "\n  %sATTACK SURFACE%s\n",
                    paint(p, C_BOLD), paint(p, C_RESET));
            for (size_t k = 0; k < e->n_metrics; k++) {
                const eg_metric_delta *m = &e->metrics[k];
                const long delta = m->to - m->from;
                fprintf(out, "    %-22s %5ld → %-5ld %s%+ld%s%s%s%s\n",
                        m->label, m->from, m->to,
                        paint(p, delta > 0 ? C_YELL : C_GREEN), delta,
                        paint(p, C_RESET),
                        paint(p, C_DIM), m->approximate ? "  (approx)" : "",
                        paint(p, C_RESET));
            }
        }

        if (e->n_deps || e->weakest_from != e->weakest_to) {
            fprintf(out, "\n  %sDEPENDENCIES%s\n",
                    paint(p, C_BOLD), paint(p, C_RESET));
            for (size_t k = 0; k < e->n_deps; k++) {
                const eg_dep_delta *dd = &e->deps[k];
                const bool worse = dd->to < dd->from;
                fprintf(out, "    %-22s %5d → %-5d %s%+d%s\n",
                        dd->name, dd->from, dd->to,
                        paint(p, worse ? C_RED : C_GREEN),
                        dd->to - dd->from, paint(p, C_RESET));
            }
            if (e->weakest_from != e->weakest_to)
                fprintf(out, "    %-22s %5d → %-5d\n",
                        "weakest dependency", e->weakest_from, e->weakest_to);
        }

        if (e->n_conf) {
            fprintf(out, "\n  %sCONFIDENCE%s\n",
                    paint(p, C_BOLD), paint(p, C_RESET));
            for (size_t k = 0; k < e->n_conf; k++) {
                const eg_conf_change *c = &e->conf[k];
                const bool lost = c->to > c->from;
                fprintf(out, "    %s%-22s%s %s → %s%s\n",
                        paint(p, lost ? C_YELL : C_GREEN), c->label,
                        paint(p, C_RESET), cname(c->from), cname(c->to),
                        lost ? "   (became harder to prove)" : "");
            }
        }
    }

    if (!any) {
        fprintf(out, "\n  %sno change in mitigations, surface, dependencies "
                     "or confidence%s\n\n",
                paint(p, C_DIM), paint(p, C_RESET));
        return;
    }

    fprintf(out, "\n%sSUMMARY%s\n", paint(p, C_BOLD), paint(p, C_RESET));
    fprintf(out, "  %zu mitigation regression%s\n", regs, regs == 1 ? "" : "s");
    fprintf(out, "  %zu attack-surface increase%s\n", surf, surf == 1 ? "" : "s");
    fprintf(out, "  %zu dependency regression%s\n", depregs, depregs == 1 ? "" : "s");
    fprintf(out, "  %zu confidence loss%s\n", confl, confl == 1 ? "" : "es");

    const char *pc = post == EG_POSTURE_DEGRADED ? C_RED
                   : post == EG_POSTURE_IMPROVED ? C_GREEN : C_DIM;
    fprintf(out, "\n  security posture: %s%s%s%s\n\n",
            paint(p, C_BOLD), paint(p, pc), posture_name(post),
            paint(p, C_RESET));
}

/* ---- trend --------------------------------------------------------------- */

void report_trend(eg_printer *p, FILE *out, const eg_trend *t)
{
    if (p->mode == EG_OUT_JSON) {
        fprintf(out, "{\n  \"tool\": \"elfguard\",\n  \"version\": \"%s\",\n"
                     "  \"mode\": \"trend\",\n  \"net_debt\": %d,\n"
                     "  \"builds_improving\": %d,\n  \"builds_degrading\": %d,\n"
                     "  \"points\": [\n",
                EG_VERSION, t->net_debt, t->improving, t->degrading);
        for (size_t i = 0; i < t->n; i++) {
            const eg_trend_point *pt = &t->points[i];
            fputs("    { \"build\": ", out);
            json_str(out, pt->build);
            fprintf(out, ", \"score\": %d, \"debt\": %d, \"grade\": \"%s\", "
                         "\"binaries\": %zu, \"unproven\": %zu, "
                         "\"delta_score\": %d, \"delta_debt\": %d, "
                         "\"regression\": %s, \"worst\": ",
                    pt->score, pt->debt, pt->grade, pt->binaries, pt->unproven,
                    pt->delta_score, pt->delta_debt,
                    pt->regression ? "true" : "false");
            json_str(out, pt->worst_binary);
            fputs(" }", out);
            if (i + 1 < t->n) fputc(',', out);
            fputc('\n', out);
        }
        fputs("  ]\n}\n", out);
        return;
    }

    fprintf(out, "\n%ssecurity posture trend%s  %s(worst binary per build)%s\n\n",
            paint(p, C_BOLD), paint(p, C_RESET),
            paint(p, C_DIM), paint(p, C_RESET));

    fprintf(out, "  %-16s %6s %6s %6s   %s\n",
            "build", "score", "debt", "grade", "");
    fprintf(out, "  %s\n", "────────────────────────────────────────────────");

    for (size_t i = 0; i < t->n; i++) {
        const eg_trend_point *pt = &t->points[i];
        const char *gc = pt->score >= 85 ? C_GREEN
                       : pt->score >= 60 ? C_YELL : C_RED;

        fprintf(out, "  %-16s %6d %6d %s%6s%s",
                pt->build, pt->score, pt->debt,
                paint(p, gc), pt->grade, paint(p, C_RESET));

        if (i > 0) {
            if (pt->regression)
                fprintf(out, "   %sREGRESSION  (score %+d, debt %+d)%s",
                        paint(p, C_RED), pt->delta_score, pt->delta_debt,
                        paint(p, C_RESET));
            else if (pt->delta_debt < 0)
                fprintf(out, "   %sdebt %+d%s", paint(p, C_GREEN),
                        pt->delta_debt, paint(p, C_RESET));
        }
        fputc('\n', out);
    }

    fprintf(out, "\n  %d build%s reduced debt, %d added it. Net debt over the "
                 "series: %s%+d%s\n",
            t->improving, t->improving == 1 ? "" : "s", t->degrading,
            paint(p, t->net_debt > 0 ? C_YELL : C_GREEN),
            t->net_debt, paint(p, C_RESET));

    if (t->net_debt > 0)
        fprintf(out, "  %sposture is accumulating debt across this series%s\n\n",
                paint(p, C_YELL), paint(p, C_RESET));
    else if (t->net_debt < 0)
        fprintf(out, "  %sposture is improving across this series%s\n\n",
                paint(p, C_GREEN), paint(p, C_RESET));
    else
        fputc('\n', out);
}

/* ---- --why ---------------------------------------------------------------
 *
 * The difference between this and a static description: the chain below is
 * assembled from *this* binary's verdicts, so the explanation of why a check
 * matters changes depending on what else is or is not in place. Telling
 * someone that CET constrains indirect branches is a manual page; telling them
 * it is the only thing left constraining indirect branches in a binary whose
 * other defences all hold is an argument for acting.
 */
void report_why(eg_printer *p, FILE *out, const eg_report *rep,
                const char *check_id, const eg_why *w)
{
    (void)rep;

    const eg_finding *t = w->target;

    fprintf(out, "\n%swhy %s matters%s\n\n",
            paint(p, C_BOLD), check_id, paint(p, C_RESET));

    fprintf(out, "  %s%s: %s%s%s\n", paint(p, C_BOLD), t->label,
            paint(p, vcolor(t->verdict)), vmark(t->verdict), paint(p, C_RESET));
    if (t->evidence[0])
        fprintf(out, "  %sevidence: %s%s\n",
                paint(p, C_GREY), t->evidence, paint(p, C_RESET));
    if (t->confidence != EG_CONF_HIGH)
        fprintf(out, "  %sconfidence: %s%s\n",
                paint(p, C_GREY), cname(t->confidence), paint(p, C_RESET));

    fprintf(out, "\n  %scurrent posture%s\n",
            paint(p, C_BOLD), paint(p, C_RESET));
    for (size_t i = 0; i < w->n_context; i++) {
        const eg_finding *f = w->context[i];
        fprintf(out, "    %-26s %s%s%s\n", f->label,
                paint(p, vcolor(f->verdict)), vmark(f->verdict),
                paint(p, C_RESET));
    }

    /* The chain: what each *passing* mitigation has already ruled out, ending
     * at what this check would have ruled out and did not. */
    fprintf(out, "\n  %sconsequence%s\n", paint(p, C_BOLD), paint(p, C_RESET));

    static const struct { const char *id, *closes; } CLOSES[] = {
        { "nx",      "code injection into writable memory" },
        { "relro",   "GOT overwrite via a single write primitive" },
        { "pie",     "hardcoded gadget addresses" },
        { "canary",  "silent return-address overwrite" },
        { "fortify", "unbounded libc copies" },
        { "cfi",     "unconstrained indirect branch targets" },
        { "wx",      "writing and executing the same page" },
    };

    bool drew = false;
    for (size_t i = 0; i < sizeof(CLOSES) / sizeof(CLOSES[0]); i++) {
        if (strcmp(CLOSES[i].id, check_id) == 0) continue;
        const eg_finding *f = eg_find(rep, CLOSES[i].id);
        if (!f || f->verdict != EG_OK) continue;

        fprintf(out, "    %s%-10s%s closes %s\n", paint(p, C_GREEN),
                f->label, paint(p, C_RESET), CLOSES[i].closes);
        fprintf(out, "               %s↓%s\n", paint(p, C_DIM), paint(p, C_RESET));
        drew = true;
    }

    const char *left = NULL;
    for (size_t i = 0; i < sizeof(CLOSES) / sizeof(CLOSES[0]); i++)
        if (strcmp(CLOSES[i].id, check_id) == 0) left = CLOSES[i].closes;

    if (t->verdict == EG_OK) {
        fprintf(out, "    %s%-10s%s closes %s\n", paint(p, C_GREEN),
                t->label, paint(p, C_RESET), left ? left : "its own class");
        fprintf(out, "\n  %sconclusion%s\n    this mitigation is in place%s\n\n",
                paint(p, C_BOLD), paint(p, C_RESET),
                drew ? " and reinforces the ones above" : "");
        return;
    }

    if (t->verdict == EG_NA) {
        fprintf(out, "    %snot applicable to this file%s\n\n",
                paint(p, C_DIM), paint(p, C_RESET));
        return;
    }

    fprintf(out, "    %s%-10s%s would close %s\n", paint(p, C_RED),
            t->label, paint(p, C_RESET), left ? left : "its own class");
    fprintf(out, "    %sbut is %s%s\n", paint(p, C_RED),
            t->verdict == EG_UNKNOWN ? "unprovable here" : "absent",
            paint(p, C_RESET));

    fprintf(out, "\n  %sconclusion%s\n", paint(p, C_BOLD), paint(p, C_RESET));
    if (t->verdict == EG_UNKNOWN)
        fprintf(out, "    %s\n\n", t->reason[0] ? t->reason
                : "the evidence needed to confirm this is not in the file");
    else if (drew)
        fprintf(out, "    with the mitigations above holding, %s is the\n"
                     "    remaining gap of its class in this binary.\n\n",
                t->label);
    else
        fprintf(out, "    %s is absent alongside other gaps; see the\n"
                     "    full report for the compounding effects.\n\n",
                t->label);
}

/* ---- dispatch ----------------------------------------------------------- */

void report_begin(eg_printer *p, FILE *out)
{
    p->first = true;
    if (p->mode == EG_OUT_JSON) {
        fprintf(out, "{\n  \"tool\": \"elfguard\",\n  \"version\": \"%s\",\n"
                     "  \"results\": [\n", EG_VERSION);
    } else if (p->mode == EG_OUT_SARIF) {
        fprintf(out,
            "{\n  \"$schema\": \"https://json.schemastore.org/sarif-2.1.0.json\",\n"
            "  \"version\": \"2.1.0\",\n  \"runs\": [\n    {\n"
            "      \"tool\": { \"driver\": {\n"
            "        \"name\": \"elfguard\",\n"
            "        \"version\": \"%s\",\n"
            "        \"informationUri\": "
            "\"https://github.com/KareemOFarahat/elfguard\",\n"
            "        \"rules\": [\n", EG_VERSION);

        /* The rule catalogue is static, so emit it from a throwaway analysis
         * of the check table rather than from whatever files happen to be
         * scanned — a rule referenced by a result must exist in the run. */
        static const struct { const char *id, *label, *desc; } RULES[] = {
            { "nx",      "NX",              "Executable stack permits direct shellcode execution." },
            { "pie",     "PIE / ASLR",      "Fixed load address removes the need for an info leak." },
            { "relro",   "RELRO",           "Writable GOT allows redirection of library calls." },
            { "canary",  "Stack canary",    "Return addresses are not validated before use." },
            { "cfi",     "CET / BTI",       "Indirect branch targets are unconstrained." },
            { "fortify", "FORTIFY coverage","Fortifiable libc calls compiled without size checks." },
            { "wx",      "W^X segments",    "A segment is both writable and executable." },
            { "rpath",   "RPATH / RUNPATH", "Hardcoded library search paths permit .so hijacking." },
            { "textrel", "Text relocations","Code pages made writable at load time." },
        };
        const size_t nr = sizeof(RULES) / sizeof(RULES[0]);
        for (size_t i = 0; i < nr; i++) {
            eg_finding f;
            memset(&f, 0, sizeof(f));
            f.id = RULES[i].id;
            f.label = RULES[i].label;
            f.impact = RULES[i].desc;
            sarif_rule(out, &f, i + 1 < nr);
        }
        fputs("        ]\n      } },\n      \"results\": [\n", out);
    }
}

void report_one(eg_printer *p, FILE *out, const eg_report *rep)
{
    switch (p->mode) {
    case EG_OUT_JSON:  print_json(p, out, rep);  break;
    case EG_OUT_SARIF: print_sarif(p, out, rep); break;
    case EG_OUT_SHORT: print_short(p, out, rep); break;
    default:           print_table(p, out, rep); break;
    }
}

void report_end(eg_printer *p, FILE *out)
{
    if (p->mode == EG_OUT_JSON)       fputs("\n  ]\n}\n", out);
    else if (p->mode == EG_OUT_SARIF) fputs("\n      ]\n    }\n  ]\n}\n", out);
    else if (p->mode == EG_OUT_TABLE) fputc('\n', out);
}
