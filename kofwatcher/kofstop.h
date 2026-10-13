/*
 * kofstop.h - "stop when the operator asks", shared by the two collectors.
 *
 * The one flag a loop polls and the handler that sets it, on both hosts.
 * It was written out in kofwatchtower.c and kofmontrace.c, character for
 * character. Each includer gets its own static g_stop.
 *
 * The handler only ASKS the loop to finish. Doing the teardown in it would run
 * it on the control handler's own thread (Windows), or free memory the main
 * thread is reading inside a blocking read (POSIX signal).
 */

#ifndef KOFWATCHER_KOFSTOP_H
#define KOFWATCHER_KOFSTOP_H

#ifdef _WIN32
static volatile LONG g_stop;

static BOOL WINAPI on_ctrl(DWORD type)
{
	(void)type;
	InterlockedExchange(&g_stop, 1);
	return TRUE;
}

static void stop_on_signal(void) { SetConsoleCtrlHandler(on_ctrl, TRUE); }
#else
static volatile sig_atomic_t g_stop;

static void on_ctrl(int sig) { (void)sig; g_stop = 1; }

static void stop_on_signal(void)
{
	signal(SIGINT, on_ctrl);
	signal(SIGTERM, on_ctrl);
}
#endif

#endif /* KOFWATCHER_KOFSTOP_H */
