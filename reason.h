/* reason.h — rule-based consequences derived from check results.
 *
 * Every statement produced here is a consequence of facts already in the
 * report, never a prediction about exploitability. See reason.c. */
#ifndef ELFGUARD_REASON_H
#define ELFGUARD_REASON_H

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>

#include "elfguard.h"

#define EG_MAX_STATEMENTS 12

typedef enum {
    EG_REASON_GAP = 0,   /* the one thing still missing        */
    EG_REASON_COMPOUND,  /* two losses that reinforce          */
    EG_REASON_BOUND,     /* posture limited by something else  */
    EG_REASON_UNPROVEN,  /* evidence missing, not mitigation   */
    EG_REASON_CONTEXT,   /* observation, explicitly not a finding */
    EG_REASON_CLEAR      /* nothing outstanding, scoped honestly  */
} eg_reason_kind;

typedef struct {
    eg_reason_kind kind;
    char           text[320];
    char           derived_from[64];   /* finding ids behind this statement */
} eg_statement;

typedef struct {
    eg_statement statements[EG_MAX_STATEMENTS];
    size_t       n;
} eg_reasoning;

typedef struct {
    const eg_finding *target;
    const eg_finding *context[EG_MAX_FINDINGS];
    size_t            n_context;
    eg_reasoning      reasoning;
} eg_why;

void        reason_run(const eg_report *rep, eg_reasoning *out);
const char *reason_kind_name(eg_reason_kind k);
bool        reason_why(const eg_report *rep, const char *check_id, eg_why *out);

#endif /* ELFGUARD_REASON_H */
