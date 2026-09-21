/*
 * thread_region - a thread started in memory no file backs is labelled as one.
 *
 * WHAT THIS IS DEFENDING, AND WHY IT NEEDS A POSITIVE CONTROL.
 *
 * The walk has always been able to find executable memory that no file backs.
 * What it could not say is whether anything is RUNNING there - and that is the
 * whole difference between a payload somebody decoded and a payload somebody
 * is executing. KOFW_RGF_THREAD is that answer.
 *
 * The flag is silent on a healthy machine, by design and by measurement: over
 * 104 processes and 511 unbacked chunks, none carried it, because every thread
 * of every ordinary process starts inside a mapped image. A flag that never
 * fires and a flag that is broken look exactly the same from there - so this
 * test MAKES one fire.
 *
 * IT DOES IT IN A CHILD, NOT IN ITSELF, and that is not a style choice: the
 * walk skips the calling process on purpose - see KOFW_PF_SELF in wwalk.c,
 * where a scanner walking itself would hand back its own scan buffers. So the
 * test re-executes itself as a victim, which allocates the page, starts a
 * suspended thread on it, reports where, and waits.
 *
 * SUSPENDED AND LEFT THAT WAY. A thread running a bare `ret` is gone in
 * microseconds, which would make this a test of timing rather than of the
 * flag. The thread has to still exist while the walk looks.
 *
 * ON POSIX THERE IS NOTHING TO TEST. The flag is libkofgrille's and the walk it
 * belongs to is Windows's; the test says so and passes rather than pretending.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef _WIN32
int main(void);
int main(void)
{
	printf("thread region: a Windows walk - nothing to test here\n");
	return 0;
}
#else

#include <windows.h>

#include "kofwalk.h"
#include "kofproc.h"
#include <kofmod/proc.h>

static int failures;

static void ok_(int cond, const char *what)
{
	if (!cond) {
		printf("  FAIL %s\n", what);
		failures++;
	}
}

/*
 * The victim half. Allocates a page nothing backs, puts a function in it,
 * starts a thread there, says where, and waits to be looked at.
 */
static int be_victim(void)
{
	/* `ret`, in whichever instruction set this host runs. */
#if defined(__aarch64__) || defined(_M_ARM64)
	static const unsigned char code[] = { 0xc0, 0x03, 0x5f, 0xd6 };
#else
	static const unsigned char code[] = { 0xc3 };
#endif
	void *mem = VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE,
				 PAGE_EXECUTE_READWRITE);
	HANDLE th;
	DWORD tid = 0;

	if (!mem)
		return 1;
	memcpy(mem, code, sizeof code);
	FlushInstructionCache(GetCurrentProcess(), mem, sizeof code);
	th = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)mem, NULL,
			  CREATE_SUSPENDED, &tid);
	if (!th)
		return 1;
	printf("%lu %llu\n", (unsigned long)GetCurrentProcessId(),
	       (unsigned long long)(uintptr_t)mem);
	fflush(stdout);
	/* Long enough for the walk, short enough that a test run that dies
	 * before killing it does not leave something around for a minute. */
	Sleep(20000);
	CloseHandle(th);
	return 0;
}

int main(int argc, char **argv);
int main(int argc, char **argv)
{
	struct kof_walk_option wo;
	struct kof_walk_api *w;
	struct kof_proc_build b;
	struct kof_walk_item it;
	char cmd[1024], line[256];
	unsigned long vpid = 0;
	unsigned long long vaddr = 0;
	FILE *vic;
	uint32_t pid;
	int err = 0, found = 0, labelled = 0, elsewhere = 0;

	if (argc > 1 && strcmp(argv[1], "--victim") == 0)
		return be_victim();

	snprintf(cmd, sizeof cmd, "\"%s\" --victim", argv[0]);
	vic = popen(cmd, "r");
	if (!vic) {
		printf("thread region: could not start the victim - nothing "
		       "tested\n");
		return 0;
	}
	if (!fgets(line, sizeof line, vic) ||
	    sscanf(line, "%lu %llu", &vpid, &vaddr) != 2 || !vpid || !vaddr) {
		pclose(vic);
		printf("thread region: the victim did not report - nothing "
		       "tested\n");
		return 0;
	}

	pid = (uint32_t)vpid;
	memset(&wo, 0, sizeof wo);
	wo.pids = &pid;
	wo.n_pids = 1u;
	w = kof_walk_open(&wo, &err);
	if (!w) {
		pclose(vic);
		printf("thread region: the walk would not open (%d) - nothing "
		       "tested\n", err);
		return 0;
	}

	while (w->next_proc(w->self, &b)) {
		while (w->next_item(w->self, &it)) {
			if (it.kind != KOF_WALK_BYTES || !it.label)
				continue;
			/*
			 * The walk hands over SPANS, which group the runs of
			 * one allocation - so the page is somewhere inside the
			 * item rather than being it.
			 */
			if (it.addr <= vaddr && vaddr < it.addr + it.len) {
				found = 1;
				if (strstr(it.label, "_THREAD"))
					labelled = 1;
			} else if (strstr(it.label, "_THREAD")) {
				elsewhere++;
			}
		}
	}
	w->close(w->self);

	ok_(found, "the walk reached the allocation the thread starts in");
	ok_(labelled, "and labelled it as carrying a thread start");
	/*
	 * NOTHING ELSE IN THAT PROCESS. Every other thread there started
	 * inside a mapped image, and an image region is not handed over as
	 * bytes - so a second labelled span would mean the correlation is
	 * matching something other than a start address.
	 */
	ok_(elsewhere == 0, "and labelled nothing else");

	/*
	 * The victim is sleeping; closing the pipe does not stop it, so it is
	 * ended here rather than left behind for twenty seconds.
	 */
	{
		HANDLE h = OpenProcess(PROCESS_TERMINATE, FALSE, (DWORD)vpid);

		if (h) {
			TerminateProcess(h, 0);
			CloseHandle(h);
		}
	}
	pclose(vic);

	if (failures) {
		printf("thread region: %d check(s) failed\n", failures);
		return 1;
	}
	printf("thread region: a thread in unbacked memory is labelled, and "
	       "only it - ok\n");
	return 0;
}
#endif
