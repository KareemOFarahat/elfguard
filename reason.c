/* reason.c — turning facts into consequences.
 *
 * The rules here are ordinary boolean logic over verdicts already produced by
 * checks.c. That is a deliberate choice and worth defending, because it would
 * be easy to reach for something cleverer and much harder to trust it.
 *
 * The constraint every rule obeys: state the *consequence of a fact*, never a
 * prediction about exploitability. "PIE and CET are both absent, so code-reuse
 * targets are both locatable and unconstrained" is a claim about the binary
 * that a reader can check against the file. "This binary is exploitable" is a
 * claim about the future that depends on reachable input, memory-safety bugs
 * we have not looked for, and the attacker's budget — none of which is in
 * scope for a static ELF reader.
 *
 * A tool that overstates gets its findings discounted wholesale, including the
 * true ones. The reasoning layer is therefore capped at what the evidence
 * supports, and each rule carries the finding ids it was derived from so the
 * reader can go check.
 */
#include <stdio.h>
#include <string.h>

#include "reason.h"

static eg_verdict verdict_of(const eg_report *rep, const char *id)
{
    const eg_finding *f = eg_find(rep, id);
    return f ? f->verdict : EG_UNKNOWN;
}

static bool failing(const eg_report *rep, const char *id)
{
    const eg_verdict v = verdict_of(rep, id);
    return v == EG_BAD || v == EG_PARTIAL;
}

static bool passing(const eg_report *rep, const char *id)
{
    return verdict_of(rep, id) == EG_OK;
}

static eg_statement *push(eg_reasoning *r, eg_reason_kind kind)
{
    if (r->n >= EG_MAX_STATEMENTS) return NULL;
    eg_statement *st = &r->statements[r->n++];
    memset(st, 0, sizeof(*st));
    st->kind = kind;
    return st;
}

static void say(eg_statement *st, const char *fmt, ...)
{
    if (!st) return;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(st->text, sizeof(st->text), fmt, ap);
    va_end(ap);
}

static void from(eg_statement *st, const char *ids)
{
    if (st) snprintf(st->derived_from, sizeof(st->derived_from), "%s", ids);
}

void reason_run(const eg_report *rep, eg_reasoning *out)
{
    memset(out, 0, sizeof(*out));
    if (!rep->is_elf) return;

    /* --- Rule 1: the remaining control-flow gap ---------------------------
     *
     * The interesting case is not "everything is off". It is the binary that
     * passes every classic check and still leaves indirect branches
     * unconstrained, because that binary looks finished and is not. */
    if (passing(rep, "nx") && passing(rep, "relro") && passing(rep, "pie") &&
        failing(rep, "cfi")) {
        eg_statement *st = push(out, EG_REASON_GAP);
        say(st, "NX, RELRO and PIE are all in place, so code injection and "
                "GOT overwrite are closed and image placement is randomised. "
                "Control-flow integrity is the one remaining hardening gap.");
        from(st, "nx relro pie cfi");
    }

    /* --- Rule 2: compounding losses -------------------------------------- */
    if (failing(rep, "pie") && failing(rep, "cfi")) {
        eg_statement *st = push(out, EG_REASON_COMPOUND);
        say(st, "PIE and control-flow integrity are both absent. Gadget "
                "addresses are fixed and indirect branch targets are "
                "unconstrained — the two properties that would each "
                "independently complicate code reuse are missing together.");
        from(st, "pie cfi");
    }

    if (failing(rep, "nx") && failing(rep, "canary")) {
        eg_statement *st = push(out, EG_REASON_COMPOUND);
        say(st, "The stack is executable and unguarded. A linear stack "
                "overflow is neither detected before return nor prevented "
                "from executing what it wrote.");
        from(st, "nx canary");
    }

    if (failing(rep, "relro") && rep->surface.plt_entries > 0) {
        eg_statement *st = push(out, EG_REASON_COMPOUND);
        say(st, "The GOT is writable and %zu PLT entries route through it, "
                "so a single write primitive reaches every one of them.",
            rep->surface.plt_entries);
        from(st, "relro");
    }

    /* --- Rule 3: bounded by a dependency ---------------------------------- */
    if (rep->weakest_dep >= 0) {
        const eg_dep *w = &rep->deps[rep->weakest_dep];
        if (w->score >= 0 && w->score < rep->score) {
            eg_statement *st = push(out, EG_REASON_BOUND);
            say(st, "This binary scores %d but loads %s at %d. Effective "
                    "posture is bounded by the dependency, not by the binary.",
                rep->score, w->name, w->score);
            from(st, "deps");
        }
    }

    /* --- Rule 4: what we cannot prove ------------------------------------- */
    if (rep->unproven > 0) {
        eg_statement *st = push(out, EG_REASON_UNPROVEN);
        say(st, "%zu check%s could not be proven from this file. The "
                "mitigation may well be present; the evidence needed to "
                "confirm it is not. Treat these as unaudited rather than "
                "as failures.",
            rep->unproven, rep->unproven == 1 ? "" : "s");
        from(st, "confidence");
    }

    /* --- Rule 5: surface observations -------------------------------------
     *
     * Phrased as context, never as a verdict. A binary that calls system()
     * may be a shell wrapper doing exactly its job. The observation earns its
     * place by being the thing a reviewer would want flagged, not by implying
     * a finding. */
    if (rep->surface.scanned && rep->surface.sensitive_imports > 0) {
        eg_statement *st = push(out, EG_REASON_CONTEXT);
        say(st, "Imports %zu sensitive libc function%s (%s). Not a finding on "
                "its own — context for reading the mitigations above.",
            rep->surface.sensitive_imports,
            rep->surface.sensitive_imports == 1 ? "" : "s",
            rep->surface.sensitive_list);
        from(st, "surface");
    }

    if (rep->surface.scanned && rep->surface.writable_segments > 0 &&
        failing(rep, "wx")) {
        eg_statement *st = push(out, EG_REASON_COMPOUND);
        say(st, "A segment is both writable and executable, so the W^X "
                "property that the rest of the mitigations assume does not "
                "hold for this image.");
        from(st, "wx");
    }

    /* --- Rule 6: the all-clear -------------------------------------------
     *
     * Worth stating explicitly, and worth stating carefully. "No gaps found"
     * is a statement about coverage of these nine checks, not a clean bill of
     * health, and the wording says so. */
    if (out->n == 0 && rep->score >= 95) {
        eg_statement *st = push(out, EG_REASON_CLEAR);
        say(st, "Every applicable mitigation is present at full strength. "
                "This says nothing about memory-safety bugs in the code "
                "itself — only that the compile-time defences against "
                "exploiting them are in place.");
        from(st, "all");
    }
}

const char *reason_kind_name(eg_reason_kind k)
{
    switch (k) {
    case EG_REASON_GAP:      return "gap";
    case EG_REASON_COMPOUND: return "compound";
    case EG_REASON_BOUND:    return "bounded";
    case EG_REASON_UNPROVEN: return "unproven";
    case EG_REASON_CONTEXT:  return "context";
    case EG_REASON_CLEAR:    return "clear";
    default:                 return "note";
    }
}

/* ---- --why: a single check, in the context of the others ----------------- */

/* Resolve what a person would type to the id the report uses.
 *
 * "cfi" is the right internal name — it is the property being checked, and it
 * covers x86 and AArch64 without privileging either. But nobody reaches for
 * it: they type CET because that is what Intel calls it, or BTI because that
 * is what the ARM docs say. Rejecting those is a usability bug dressed up as
 * correctness, so accept the vocabulary people actually have. */
static const char *canonical_id(const char *in)
{
    static const struct { const char *alias, *id; } MAP[] = {
        { "cet", "cfi" }, { "ibt", "cfi" }, { "shstk", "cfi" },
        { "bti", "cfi" }, { "pac", "cfi" }, { "cfi", "cfi" },
        { "aslr", "pie" }, { "pie", "pie" },
        { "nx", "nx" }, { "dep", "nx" }, { "noexecstack", "nx" },
        { "relro", "relro" }, { "bindnow", "relro" },
        { "canary", "canary" }, { "ssp", "canary" },
        { "stackprotector", "canary" }, { "stack-protector", "canary" },
        { "fortify", "fortify" }, { "fortify_source", "fortify" },
        { "wx", "wx" }, { "w^x", "wx" }, { "rwx", "wx" },
        { "rpath", "rpath" }, { "runpath", "rpath" },
        { "textrel", "textrel" }, { "textrels", "textrel" },
    };

    char low[64];
    size_t n = 0;
    for (; in[n] && n + 1 < sizeof(low); n++) {
        char c = in[n];
        low[n] = (c >= 'A' && c <= 'Z') ? (char)(c - 'A' + 'a') : c;
    }
    low[n] = '\0';

    for (size_t i = 0; i < sizeof(MAP) / sizeof(MAP[0]); i++)
        if (strcmp(MAP[i].alias, low) == 0) return MAP[i].id;

    return NULL;
}

bool reason_why(const eg_report *rep, const char *check_id, eg_why *out)
{
    memset(out, 0, sizeof(*out));

    const char *id = canonical_id(check_id);
    const eg_finding *target = id ? eg_find(rep, id) : eg_find(rep, check_id);
    if (!target) return false;

    out->target = target;

    /* The chain is what makes --why different from a static description: it
     * walks the mitigations that *do* hold, so the explanation of why this one
     * matters is grounded in this binary's actual posture rather than in a
     * paragraph that would read identically for every file. */
    static const char *const ORDER[] = {
        "nx", "relro", "pie", "canary", "fortify", "cfi", "wx", "textrel",
    };

    for (size_t i = 0; i < sizeof(ORDER) / sizeof(ORDER[0]); i++) {
        const eg_finding *f = eg_find(rep, ORDER[i]);
        if (!f || out->n_context >= EG_MAX_FINDINGS) continue;
        out->context[out->n_context++] = f;
    }

    reason_run(rep, &out->reasoning);
    return true;
}
