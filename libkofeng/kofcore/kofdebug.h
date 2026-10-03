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

#endif /* KOFENG_KOFDEBUG_H */
