/*
 * shared - built as a library, so the collectors meet the other object type.
 *
 * ELF calls it ET_DYN and PE calls it a DLL, and both differ from an executable in
 * ways a parser has to handle: an entry point that is not a program's, exports
 * where an executable has none, and on ELF the same type a position independent
 * executable carries - which is exactly the ambiguity worth having a fixture for.
 */
#if defined(_WIN32)
#define KOF_EXPORT __declspec(dllexport)
#else
#define KOF_EXPORT __attribute__((visibility("default")))
#endif

static const char marker[] = "kofeng-fixture-shared";

KOF_EXPORT const char *kof_fixture_name(void)
{
	return marker;
}

KOF_EXPORT int kof_fixture_add(int a, int b)
{
	return a + b;
}

#if defined(_WIN32)
int __stdcall DllMainCRTStartup(void *h, unsigned long r, void *p)
{
	(void)h; (void)r; (void)p;
	return 1;
}
#endif
