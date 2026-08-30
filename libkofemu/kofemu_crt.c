/*
 * kofemu_crt.c - the C runtime bddisasm asks its integrator for.
 *
 * bddisasm deliberately calls no libc. It is built to run inside a kernel, a
 * hypervisor, or anywhere else that has no runtime to link against, so it
 * declares the two primitives it needs and leaves them to whoever embeds it -
 * see libkofemu/bddisasm/src/include/bddisasm_crt.h.
 *
 * kofeng is a user-space program with a libc, so the answers are one line each.
 * They live HERE rather than in the vendored tree because the vendored tree is
 * unmodified and has to stay that way: an upgrade of bddisasm is then a copy
 * rather than a merge, and this file is the seam that makes that true.
 *
 * nd_vsnprintf_s is used only by NdToText, which kofeng needs for tracing an
 * emulated instruction stream and for nothing else. If the formatter is ever
 * dropped from the build this becomes dead and should go with it.
 */

#include <stdio.h>
#include <stdarg.h>
#include <string.h>

#include "bddisasm_types.h"
/* For the prototypes, so the definitions below are checked against the
 * declarations bddisasm actually calls rather than merely matching by name. */
#include "bddisasm_crt.h"

int nd_vsnprintf_s(char *buffer, ND_SIZET sizeOfBuffer, ND_SIZET count,
		   const char *format, va_list arglist)
{
	/*
	 * `count` is the caller's own cap and may be ND_SIZET(-1) for "as much as
	 * fits", which is how the CRT's _vsnprintf_s spells it. vsnprintf takes
	 * one size, so the smaller of the two is the honest one to give it.
	 */
	ND_SIZET n = count < sizeOfBuffer ? count : sizeOfBuffer;

	if (n == 0)
		return 0;
	return vsnprintf(buffer, (size_t)n, format, arglist);
}

void *nd_memset(void *s, int c, ND_SIZET n)
{
	return memset(s, c, (size_t)n);
}
