/* freestanding: a loop, a named callee, and raw syscalls with a known number */
static long sys3(long n, long a, long b, long c)
{
	long r;

	__asm__ volatile("syscall" : "=a"(r) : "a"(n), "D"(a), "S"(b), "d"(c)
			 : "rcx", "r11", "memory");
	return r;
}

__attribute__((noinline)) long emit(const char *s, long n)
{
	return sys3(1, 1, (long)s, n);
}

__attribute__((noinline)) long spin(long n)
{
	long i, t = 0;

	for (i = 0; i < n; i++)
		t += i * 3;
	return t;
}

void _start(void)
{
	emit("hi\n", 3);
	spin(100);
	sys3(60, 0, 0, 0);
	for (;;)
		;
}
