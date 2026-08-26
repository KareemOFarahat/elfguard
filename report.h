#ifndef ELFGUARD_REPORT_H
#define ELFGUARD_REPORT_H

#include <stdbool.h>
#include <stdio.h>

#include "diff.h"
#include "reason.h"
#include "trend.h"
#include "elfguard.h"

typedef enum {
    EG_OUT_TABLE,
    EG_OUT_JSON,
    EG_OUT_SHORT,
    EG_OUT_SARIF
} eg_outmode;

typedef struct {
    eg_outmode mode;
    bool       color;
    bool       explain;   /* print the "why it matters" impact text */
    bool       deps;      /* render the dependency tree             */
    bool       surface;   /* render the attack-surface inventory    */
    bool       reason;    /* render derived consequences            */
    bool       first;     /* JSON/SARIF comma bookkeeping           */
} eg_printer;

void report_begin(eg_printer *p, FILE *out);
void report_one(eg_printer *p, FILE *out, const eg_report *rep);
void report_end(eg_printer *p, FILE *out);

/* These views have their own begin/end and are not part of the file loop. */
void report_diff(eg_printer *p, FILE *out, const eg_diff *d);
void report_trend(eg_printer *p, FILE *out, const eg_trend *t);
void report_why(eg_printer *p, FILE *out, const eg_report *rep,
                const char *check_id, const eg_why *w);

#endif /* ELFGUARD_REPORT_H */
