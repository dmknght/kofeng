/*
 * sections - one object with every section kind a real binary has.
 *
 * Initialised data, read-only data, zero-filled data, thread local storage and a
 * constructor, each large enough that the linker gives it its own section with a
 * size worth checking rather than folding it into a neighbour. This is what makes
 * the region partition mean something: a file with one section proves nothing
 * about a resolver that has to place five and leave no byte in two of them.
 */
#include <stdio.h>

const  char rodata_blob[4096] = "kofeng-fixture-rodata";
       char data_blob[4096]   = "kofeng-fixture-data";
       char bss_blob[8192];
_Thread_local int tls_counter = 1;

__attribute__((constructor)) static void ctor(void)
{
	bss_blob[0] = 'c';
}

int main(void)
{
	printf("%s %s %d\n", rodata_blob, data_blob, tls_counter + bss_blob[0]);
	return 0;
}
