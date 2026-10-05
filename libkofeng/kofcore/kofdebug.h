/*
 * kofdebug.h - the diagnostic output, and WHEN it exists.
 *
 * IT IS A COMPILE-TIME DECISION AND NOT A RUNTIME ONE.
 *
 * Every one of these used to be `if (getenv("KOF_EMU_TRACE"))`, and that is
 * wrong twice over. It puts a lookup of the process environment on paths that
 * run millions of times - one of them was measured costing four times the
 * work it guarded - and it means a shipped scanner carries, and can be made
 * to execute, code that exists only for whoever was debugging it. An engine's
 * behaviour should not depend on what is in the environment it was started
 * in.
 *
 * So the build decides. `make` leaves KOF_DEBUG undefined and every call
 * below compiles to nothing: no string, no branch, no format. `make DEBUG=1`
 * defines it and they print.
 *
 * THE ARGUMENTS ARE STILL CHECKED when it is off, because the call sits in a
 * `sizeof` of the expression - so a format that does not match its arguments
 * is a compile error in a release build too, which is the one thing a
 * #ifdef'd-out block cannot promise.
 */
#ifndef KOFENG_KOFDEBUG_H
#define KOFENG_KOFDEBUG_H

#include <stdio.h>

#ifndef KOF_DEBUG
#define KOF_DEBUG 0
#endif

#if KOF_DEBUG
#define KOF_TRACE(...)   ((void)fprintf(stderr, __VA_ARGS__))
#define KOF_TRACING      1
#else
#define KOF_TRACE(...)   ((void)sizeof(printf(__VA_ARGS__)))
#define KOF_TRACING      0
#endif

/*
 * ---- WHERE THE TIME WENT -------------------------------------------------
 *
 * The same build decision as the tracing above, and it lives here rather than
 * in a file of its own: it is one more thing that exists only while somebody
 * is looking, and a module is a thing the engine DOES. Splitting it out made
 * it look like a facility the product has.
 *
 * A clock read is not free - CLOCK_MONOTONIC is a vDSO call - so a release
 * build takes none: no clock, no table, no branch.
 *
 * A SLOT IS AN ENUM AND NOT A STRING. The name is wanted in the report, not
 * on the path: a string would mean a hash or a compare at every stage
 * boundary, and the boundaries are where a bottleneck hides, so measuring
 * them must not move them.
 *
 * NESTED ENTRIES ARE COUNTED, NOT TIMED TWICE. A stage that re-enters itself
 * - an unpacker whose child is unpacked again - is timed from the outermost
 * entry to the matching exit, which is the wall time that stage really cost.
 *
 * The slot is still CHECKED in a release build, in a `sizeof`, so a name that
 * no longer exists is a compile error in both builds rather than in one.
 */
/*
 * THE STAGES. One row per thing that can be the answer to "what is slow",
 * and no finer: a report with sixty rows is a second profiling problem.
 */
enum kof_time_slot {
	KOF_T_DB_LOAD = 0,      /* reading the database in               */
	KOF_T_PARSE,            /* working out what an object IS         */
	KOF_T_UNPACK,           /* an unpacker module, static or emulated */
	KOF_T_EMU,              /* the interpreter itself                */
	KOF_T_MATCH,            /* the pattern and string engines        */
	KOF_T_DIAG_SYSCALL,     /* the syscall sweep                     */
	KOF_T_DIAG_SYMBOL,      /* the import walk                       */
	KOF_T_DIAG_EMULATE,     /* the span runner                       */
	KOF_T_DIAG_MATCH,       /* fitting diagnoses to what was found   */
	KOF_T_COUNT
};

#if KOF_DEBUG
void kof_time_begin(enum kof_time_slot s);
void kof_time_end(enum kof_time_slot s);
/* Prints the table, slowest first, and zeroes it. Called by a tool when it
 * has finished - never by the engine, which does not decide what is shown. */
void kof_time_report(void);

#define KOF_TIME_BEGIN(s)  kof_time_begin(s)
#define KOF_TIME_END(s)    kof_time_end(s)
#define KOF_TIME_REPORT()  kof_time_report()
#else
#define KOF_TIME_BEGIN(s)  ((void)sizeof(s))
#define KOF_TIME_END(s)    ((void)sizeof(s))
#define KOF_TIME_REPORT()  ((void)0)
#endif


#endif /* KOFENG_KOFDEBUG_H */
