/*
 * plain - the smallest thing a collector should get entirely right.
 *
 * One function, one string, nothing unusual. It is the control: anything a parser
 * reports about this file that is not plainly true is a bug in the parser rather
 * than a property of an odd input.
 */
#include <stdio.h>

static const char marker[] = "kofeng-fixture-plain";

int main(void)
{
	printf("%s\n", marker);
	return 0;
}
