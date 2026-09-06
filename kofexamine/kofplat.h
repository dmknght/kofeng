/*
 * kofplat.h - what a terminal tool needs from the operating system.
 *
 * The engine has kofplatform.h for its own split - mapping, memmem, stat - and
 * this is the same idea one layer up: the handful of things kofviewer needs
 * that POSIX and Windows spell differently, each behind one name, with both
 * spellings in this file and none of them in the viewer.
 *
 * WHY A HEADER AND NOT #ifdef AT THE CALL SITES. kofviewer.c is fifteen
 * thousand lines of drawing and input handling, none of which is about an
 * operating system. Conditional compilation scattered through it would put a
 * platform question in front of every reader of a layout routine, and - the
 * part that actually costs - would make the two builds diverge in places
 * nobody is looking at. Here the divergence is the whole subject of the file.
 *
 * WHAT IS NOT HERE. The escape sequences are not a platform difference: the
 * alternate screen, SGR mouse reporting and bracketed paste are ANSI, and a
 * Windows console that has had ENABLE_VIRTUAL_TERMINAL_PROCESSING turned on
 * reads them exactly as an xterm does. Turning that on IS a difference, so it
 * is in kof_tty_raw_enter; the sequences themselves stay in the viewer where
 * the drawing is.
 */
#ifndef KOFENG_KOFPLAT_H
#define KOFENG_KOFPLAT_H

#include <stddef.h>
#include <stdio.h>
#include <string.h>

#ifdef _WIN32

#include <windows.h>
#include <io.h>
#include <direct.h>
#include <limits.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <stdlib.h>

/* ---- terminal ---------------------------------------------------------- */

static HANDLE kof_in_h(void)  { return GetStdHandle(STD_INPUT_HANDLE); }
static HANDLE kof_out_h(void) { return GetStdHandle(STD_OUTPUT_HANDLE); }

static DWORD kof_saved_in_mode, kof_saved_out_mode;
static int   kof_mode_saved;

static int kof_tty_ok(void)
{
	DWORD m;

	return GetConsoleMode(kof_in_h(), &m) && GetConsoleMode(kof_out_h(), &m);
}

/*
 * Raw input and an ANSI-speaking output, which on Windows are two separate
 * switches on two separate handles.
 *
 * ENABLE_VIRTUAL_TERMINAL_PROCESSING is what makes every escape sequence in
 * the viewer mean anything; without it they are printed as text. It has been
 * available since Windows 10 1511, and a console too old to accept it fails
 * here rather than drawing garbage.
 *
 * On the input side ENABLE_VIRTUAL_TERMINAL_INPUT is what turns arrow keys and
 * mouse reports into the same escape sequences the POSIX side reads, so
 * read_key in the viewer needs no second implementation. Line input, echo and
 * processed input all go off for the reason the termios flags go off: the
 * viewer wants bytes, not lines, and wants Ctrl-C as a keystroke rather than
 * as a signal.
 */
static int kof_tty_raw_enter(void)
{
	DWORD in_mode, out_mode;

	if (!GetConsoleMode(kof_in_h(), &kof_saved_in_mode) ||
	    !GetConsoleMode(kof_out_h(), &kof_saved_out_mode))
		return 0;
	kof_mode_saved = 1;

	in_mode = kof_saved_in_mode;
	in_mode &= (DWORD)~(ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT |
			    ENABLE_PROCESSED_INPUT);
	in_mode |= ENABLE_VIRTUAL_TERMINAL_INPUT | ENABLE_WINDOW_INPUT;

	out_mode = kof_saved_out_mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING;

	if (!SetConsoleMode(kof_out_h(), out_mode))
		return 0;
	if (!SetConsoleMode(kof_in_h(), in_mode)) {
		SetConsoleMode(kof_out_h(), kof_saved_out_mode);
		return 0;
	}
	return 1;
}

static void kof_tty_raw_leave(void)
{
	if (!kof_mode_saved)
		return;
	kof_mode_saved = 0;
	SetConsoleMode(kof_in_h(), kof_saved_in_mode);
	SetConsoleMode(kof_out_h(), kof_saved_out_mode);
}

/*
 * The WINDOW, not the buffer.
 *
 * srWindow is the part on screen; dwSize is the scrollback, which on a default
 * console is three hundred rows tall. Laying out to dwSize would draw most of
 * the screen where nobody can see it.
 */
static int kof_tty_size(int *rows, int *cols)
{
	CONSOLE_SCREEN_BUFFER_INFO csbi;

	if (!GetConsoleScreenBufferInfo(kof_out_h(), &csbi))
		return 0;
	*rows = csbi.srWindow.Bottom - csbi.srWindow.Top + 1;
	*cols = csbi.srWindow.Right - csbi.srWindow.Left + 1;
	return *rows > 0 && *cols > 0;
}

/*
 * There is no SIGWINCH, so a resize is noticed by looking.
 *
 * ENABLE_WINDOW_INPUT does put WINDOW_BUFFER_SIZE_EVENT in the input queue,
 * and reading it would mean draining events the viewer's key reader has to see
 * - two consumers of one queue, racing. Comparing the size costs one call per
 * frame against a console that is redrawn on a keystroke, and cannot lose an
 * event to whoever read the queue first.
 */
static int kof_seen_rows, kof_seen_cols;

static int kof_tty_resize_pending(void)
{
	int r = 0, c = 0;

	if (!kof_tty_size(&r, &c))
		return 0;
	return r != kof_seen_rows || c != kof_seen_cols;
}

static void kof_tty_resize_clear(void)
{
	kof_tty_size(&kof_seen_rows, &kof_seen_cols);
}

/* ---- input ------------------------------------------------------------- */

/*
 * Whether a keystroke is waiting, with `ms` of patience.
 *
 * WaitForSingleObject on the console handle rather than PeekConsoleInput: the
 * handle is signalled by any input record, and the viewer's reader consumes
 * them. Peeking would have to classify records here to avoid reporting a
 * resize as a keystroke, which is the reader's job and would then be done
 * twice.
 */
static int kof_in_ready(int ms)
{
	DWORD w = WaitForSingleObject(kof_in_h(),
				      ms < 0 ? INFINITE : (DWORD)ms);

	return w == WAIT_OBJECT_0;
}

/* ---- clipboard --------------------------------------------------------- */

/*
 * ONLY ON THIS SIDE, AND THE ASYMMETRY IS THE POINT.
 *
 * Windows has a clipboard: one owner, one API, always present. X11 and Wayland
 * do not - what they have is a convention between running programs, reached by
 * spawning wl-copy, xclip or xsel and hoping one of them is installed. So the
 * POSIX path is not a system call wearing a different name, it is a different
 * mechanism, and it stays in the viewer next to the helper table it needs.
 *
 * CF_UNICODETEXT rather than CF_TEXT: the console is UTF-8 and CF_TEXT is the
 * system code page, so a path with a non-ASCII character would come back as
 * different bytes than it went in. The conversion is done here, once, rather
 * than leaving the caller to discover that the round trip is lossy.
 */
static int kof_clip_put(const char *bytes, size_t n)
{
	int wn;
	HGLOBAL h;
	wchar_t *w;
	int ok = 0;

	if (n > (size_t)INT_MAX)
		return 0;
	wn = MultiByteToWideChar(CP_UTF8, 0, bytes, (int)n, NULL, 0);
	if (wn <= 0)
		return 0;
	h = GlobalAlloc(GMEM_MOVEABLE, ((size_t)wn + 1u) * sizeof(wchar_t));
	if (!h)
		return 0;
	w = (wchar_t *)GlobalLock(h);
	if (!w) {
		GlobalFree(h);
		return 0;
	}
	MultiByteToWideChar(CP_UTF8, 0, bytes, (int)n, w, wn);
	w[wn] = L'\0';
	GlobalUnlock(h);

	if (OpenClipboard(NULL)) {
		EmptyClipboard();
		/* The clipboard owns the block once SetClipboardData succeeds,
		 * so it is only freed on the path where it does not. */
		if (SetClipboardData(CF_UNICODETEXT, h))
			ok = 1;
		CloseClipboard();
	}
	if (!ok)
		GlobalFree(h);
	return ok;
}

static size_t kof_clip_get(char *out, size_t cap)
{
	HANDLE h;
	const wchar_t *w;
	int got = 0;

	if (!cap || !OpenClipboard(NULL))
		return 0;
	h = GetClipboardData(CF_UNICODETEXT);
	if (h) {
		w = (const wchar_t *)GlobalLock(h);
		if (w) {
			got = WideCharToMultiByte(CP_UTF8, 0, w, -1, out,
						  (int)cap, NULL, NULL);
			GlobalUnlock(h);
			/* The count includes the terminator this returns
			 * without; a failed conversion is zero either way. */
			if (got > 0)
				got--;
		}
	}
	CloseClipboard();
	return (size_t)(got > 0 ? got : 0);
}

/*
 * Where a scratch file may be written, as a template for mkstemp.
 *
 * The variable differs and so does the fallback: POSIX has TMPDIR and /tmp,
 * Windows has TEMP or TMP and no directory that is guaranteed to exist by
 * convention - so the current directory is the last resort there rather than a
 * hard-coded path that may not be writable or may not exist at all.
 */

/*
 * A scratch file with no name, for an object too large to hold in memory.
 *
 * TWO DIFFERENCES IN ONE CALL, and both are silent failures if ignored.
 *
 * _O_BINARY: the CRT opens in TEXT mode by default, and a text-mode write
 * turns every 0x0A into 0x0D 0x0A. The bytes being spilled here are a scanned
 * object - arbitrary binary - so text mode does not merely add characters, it
 * shifts everything after the first newline and the mapping reads back a file
 * that is not the one written.
 *
 * _O_TEMPORARY: POSIX unlinks the name immediately and lets the open
 * descriptor keep the file alive, which is the trick the engine's own
 * kof_src_tmpfile documents. Windows refuses to delete a file that is open, so
 * the unlink fails and the file is left behind - once per spilled object, for
 * the life of the machine. _O_TEMPORARY asks the system to delete it when the
 * last handle closes, which is the same guarantee arrived at from the other
 * end.
 */

/* ---- running a command ------------------------------------------------- */

/*
 * Run `argv` in `dir`, with both its output streams going to `fd`, and wait.
 * Non-zero when it ran and exited zero.
 *
 * CreateProcess takes ONE COMMAND LINE, not an argument vector, and the child
 * is what splits it again - so anything with a space in it has to be quoted
 * here or it arrives as two arguments. The rule below is the documented one:
 * wrap in quotes, double any embedded quote, and double the run of backslashes
 * that precedes one.
 *
 * bInheritHandles must be TRUE and the handle made inheritable, or the child
 * gets no output at all and the log this exists to write comes back empty.
 */
static int kof_run_to_fd(const char *dir, const char *const *argv, int fd)
{
	char cmd[4096];
	size_t at = 0;
	int i;
	HANDLE h;
	STARTUPINFOA si;
	PROCESS_INFORMATION pi;
	DWORD code = 1;

	for (i = 0; argv[i]; i++) {
		const char *a = argv[i];
		size_t j;

		if (at + 3u >= sizeof cmd)
			return 0;
		if (i)
			cmd[at++] = ' ';
		cmd[at++] = '"';
		for (j = 0; a[j]; j++) {
			size_t bs = 0;

			while (a[j] == '\\') { bs++; j++; }
			if (!a[j]) {          /* trailing run, before the quote */
				bs *= 2u;
				while (bs-- && at + 2u < sizeof cmd)
					cmd[at++] = '\\';
				break;
			}
			if (a[j] == '"')
				bs = bs * 2u + 1u;
			while (bs-- && at + 2u < sizeof cmd)
				cmd[at++] = '\\';
			if (at + 2u >= sizeof cmd)
				return 0;
			cmd[at++] = a[j];
		}
		if (at + 2u >= sizeof cmd)
			return 0;
		cmd[at++] = '"';
	}
	cmd[at] = '\0';

	h = (HANDLE)_get_osfhandle(fd);
	if (h == INVALID_HANDLE_VALUE)
		return 0;
	if (!SetHandleInformation(h, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT))
		return 0;

	memset(&si, 0, sizeof si);
	si.cb = sizeof si;
	si.dwFlags = STARTF_USESTDHANDLES;
	si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
	si.hStdOutput = h;
	si.hStdError = h;
	memset(&pi, 0, sizeof pi);

	if (!CreateProcessA(NULL, cmd, NULL, NULL, TRUE, CREATE_NO_WINDOW,
			    NULL, dir, &si, &pi))
		return 0;
	WaitForSingleObject(pi.hProcess, INFINITE);
	GetExitCodeProcess(pi.hProcess, &code);
	CloseHandle(pi.hThread);
	CloseHandle(pi.hProcess);
	return code == 0;
}

/* ---- paths ------------------------------------------------------------- */

static int kof_getcwd(char *out, size_t cap)
{
	return _getcwd(out, (int)cap) != NULL;
}

#else /* POSIX */

#include <unistd.h>
#include <poll.h>
#include <signal.h>
#include <termios.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <stdlib.h>

/* ---- terminal ---------------------------------------------------------- */

static struct termios kof_saved_tty;
static int            kof_mode_saved;

static int kof_tty_ok(void)
{
	return isatty(STDIN_FILENO) && isatty(STDOUT_FILENO);
}

static int kof_tty_raw_enter(void)
{
	struct termios raw;

	if (tcgetattr(STDIN_FILENO, &kof_saved_tty) != 0)
		return 0;
	kof_mode_saved = 1;
	raw = kof_saved_tty;
	/* No echo, no line discipline, no signals from keys, and a read that
	 * returns as soon as one byte is there. */
	raw.c_lflag &= (tcflag_t)~(ECHO | ICANON | IEXTEN | ISIG);
	raw.c_iflag &= (tcflag_t)~(IXON | ICRNL | BRKINT | INPCK | ISTRIP);
	raw.c_oflag &= (tcflag_t)~OPOST;
	raw.c_cc[VMIN] = 1;
	raw.c_cc[VTIME] = 0;
	return tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw) == 0;
}

static void kof_tty_raw_leave(void)
{
	if (!kof_mode_saved)
		return;
	kof_mode_saved = 0;
	tcsetattr(STDIN_FILENO, TCSAFLUSH, &kof_saved_tty);
}

static int kof_tty_size(int *rows, int *cols)
{
	struct winsize ws;

	if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) != 0 ||
	    !ws.ws_row || !ws.ws_col)
		return 0;
	*rows = ws.ws_row;
	*cols = ws.ws_col;
	return 1;
}

static volatile sig_atomic_t kof_winch;

static void kof_on_winch(int sig)
{
	(void)sig;
	kof_winch = 1;
}

/* Installed here so the signal and the flag that reads it stay together.
 * Without SA_RESTART on purpose: the point is for a blocked read to come back
 * so the loop can lay the screen out again. */
static void kof_tty_watch_size(void)
{
	struct sigaction sa;

	memset(&sa, 0, sizeof sa);
	sa.sa_handler = kof_on_winch;
	sigemptyset(&sa.sa_mask);
	sigaction(SIGWINCH, &sa, NULL);
}

/*
 * Asked and cleared separately, because the viewer does both at different
 * moments: the reader reports a resize when a blocked read comes back on the
 * signal, and the draw loop is what has actually dealt with it. One function
 * that consumed would let whichever ran first hide the resize from the other.
 */
static int kof_tty_resize_pending(void)
{
	return kof_winch != 0;
}

static void kof_tty_resize_clear(void)
{
	kof_winch = 0;
}

/* ---- input ------------------------------------------------------------- */

static int kof_in_ready(int ms)
{
	struct pollfd p;

	p.fd = STDIN_FILENO;
	p.events = POLLIN;
	p.revents = 0;
	return poll(&p, 1, ms) > 0 && (p.revents & POLLIN) != 0;
}


/* A scratch file with no name: unlinked at once, kept alive by the descriptor.
 * There is no text mode to turn off. */

/* ---- running a command ------------------------------------------------- */

/* Run `argv` in `dir`, both output streams to `fd`, and wait. Non-zero when it
 * ran and exited zero. */
static int kof_run_to_fd(const char *dir, const char *const *argv, int fd)
{
	pid_t pid;
	int status = 0;

	pid = fork();
	if (pid < 0)
		return 0;
	if (pid == 0) {
		if (chdir(dir) != 0)
			_exit(127);
		dup2(fd, 1);
		dup2(fd, 2);
		close(fd);
		/*
		 * execvp's second parameter is char *const[] and it does not
		 * write through it - the missing const is a wart older than
		 * this program. Cast through a union rather than straight,
		 * because casting the const away directly is what -Wcast-qual
		 * exists to catch and silencing that warning file-wide would
		 * hide the casts that are real.
		 */
		union { const char *const *c; char *const *v; } u;

		u.c = argv;
		execvp(argv[0], u.v);
		_exit(127);
	}
	while (waitpid(pid, &status, 0) < 0 && errno == EINTR)
		;
	return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

/* ---- paths ------------------------------------------------------------- */

static int kof_getcwd(char *out, size_t cap)
{
	return getcwd(out, cap) != NULL;
}

#endif /* _WIN32 */

/*
 * Windows has no SIGWINCH to install, and kof_tty_resized there looks rather
 * than waits - so this exists on both sides and does nothing on one, which is
 * better than a caller that has to know which platform it is on.
 */
#ifdef _WIN32
static void kof_tty_watch_size(void) { }
#endif

#endif /* KOFENG_KOFPLAT_H */
