/*
 * ref_shim - the two C-runtime functions the reference x86 decoder asks its
 * integrator for, so tools/genotype/x86_gen.c and x86_diff.c can link it.
 *
 * It is a dev-tool file: nothing in the engine links it, and neither does the
 * reference decoder (see THIRD-PARTY.md).
 */
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

void *nd_memset(void *s, int c, size_t n)
{
	return memset(s, c, n);
}

int nd_vsnprintf_s(char *buffer, size_t size, size_t count, const char *format,
		   va_list ap)
{
	(void)count;
	return vsnprintf(buffer, size, format, ap);
}
