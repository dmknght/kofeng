#define _GNU_SOURCE
#include "kv.h"

/* Which helper took the last copy, or NULL when only this program has it. */
static const char *g_clip_via;

static void copy_take(const char *bytes, size_t n)
{
	/*
	 * ONE BYTE SHORT OF THE BUFFER, AND TERMINATED.
	 *
	 * This filled g_clip to the last byte and wrote no NUL, so a full
	 * clipboard was a char array with no end. Both readers today take the
	 * pointer AND g_clip_n - see paste_src - so nothing runs off it; the
	 * next one to reach for %s or strlen would, and it would look like a
	 * clipboard bug rather than a read past a static.
	 *
	 * Every other clamp on this path already spells it this way
	 * (sizeof - 1, then terminate). The cost is one byte of a 8192-byte
	 * clipboard, which is not a paste anybody notices.
	 */
	g_clip_n = n < sizeof g_clip - 1u ? n : sizeof g_clip - 1u;
	memcpy(g_clip, bytes, g_clip_n);
	g_clip[g_clip_n] = '\0';
}

/*
 * The system clipboard through a helper program, when the terminal will not.
 *
 * OSC 52 is the right primary because it is the only one that crosses ssh, but
 * it asks the TERMINAL for a favour and the common ones refuse: VTE - so
 * gnome-terminal and xfce4-terminal - ships with clipboard writes disabled, and
 * there is no reply, so the copy fails silently and a clipboard manager never
 * sees a thing. Measured rather than assumed: the sequence goes out correctly
 * with the right bytes in it and nothing arrives at the other end.
 *
 * So a local session gets a local answer. This is the only place this program
 * starts another process, and it is written to be unable to disturb the one
 * thing a TUI cannot afford to lose: the child's output goes to /dev/null and
 * its input is a pipe, so it can never write to the terminal this is drawing on.
 *
 * Returns the helper's name, or NULL when none of them is installed.
 */
/*
 * COPY AND PASTE ARE THE ONE PLACE THE TWO SYSTEMS DIFFER IN KIND.
 *
 * Windows has a clipboard and the calls below reach it. X11 and Wayland have a
 * convention between running programs, so the POSIX half spawns whichever of
 * wl-copy, xclip or xsel is installed and treats "none of them are" as a normal
 * answer - which is why the OSC 52 fallback after this exists at all.
 *
 * Split whole rather than per statement: there is no shared shape to factor
 * out, and pretending there is would mean a function whose two halves have
 * nothing in common but a name.
 */
#ifdef _WIN32

/* Returns what to name in the status line, the way the POSIX side returns
 * whichever helper worked. */
static const char *copy_extern(const char *bytes, size_t n)
{
	return kof_clip_put(bytes, n) ? "clipboard" : NULL;
}

size_t paste_extern(char *out, size_t cap)
{
	return kof_clip_get(out, cap);
}

#else /* POSIX */

static const char *copy_extern(const char *bytes, size_t n)
{
	static const char *const helper[][4] = {
		{ "wl-copy", NULL, NULL, NULL },
		{ "xclip", "-selection", "clipboard", NULL },
		{ "xsel", "-i", "-b", NULL }
	};
	size_t h;

	for (h = 0; h < sizeof helper / sizeof helper[0]; h++) {
		int fds[2];
		pid_t pid;
		int status = 0;
		void (*old)(int);

		if (pipe(fds) != 0)
			return NULL;
		pid = fork();
		if (pid < 0) {
			close(fds[0]);
			close(fds[1]);
			return NULL;
		}
		if (pid == 0) {
			int devnull = open("/dev/null", O_WRONLY);

			dup2(fds[0], STDIN_FILENO);
			if (devnull >= 0) {
				dup2(devnull, STDOUT_FILENO);
				dup2(devnull, STDERR_FILENO);
			}
			close(fds[0]);
			close(fds[1]);
			/*
			 * execvp wants char *const[] and is documented not to
			 * modify what it points at - a signature older than
			 * const itself. The copy is made here rather than
			 * casting the table, so the strings stay const
			 * everywhere they are actually read.
			 */
			{
				char *argv[4];
				size_t a;

				for (a = 0; a < 4u; a++)
					argv[a] = helper[h][a]
						  ? strdup(helper[h][a]) : NULL;
				execvp(argv[0], argv);
			}
			_exit(127);
		}
		close(fds[0]);
		/* A helper that is not installed exits before reading, and the
		 * write would then take this process down with SIGPIPE. */
		old = signal(SIGPIPE, SIG_IGN);
		{
			size_t at = 0;

			while (at < n) {
				ssize_t w = write(fds[1], bytes + at, n - at);

				if (w <= 0)
					break;
				at += (size_t)w;
			}
		}
		close(fds[1]);
		signal(SIGPIPE, old);
		if (waitpid(pid, &status, 0) == pid &&
		    WIFEXITED(status) && WEXITSTATUS(status) == 0)
			return helper[h][0];
	}
	return NULL;
}

/*
 * THE SYSTEM CLIPBOARD, READ back through a helper - the other half of
 * copy_extern.
 *
 * Ctrl+V used to paste this program's OWN last copy, held in g_clip, because the
 * only clipboard it could reach was the one it wrote. But copy already reaches
 * the system clipboard through wl-copy/xclip/xsel, and the same tools read it:
 * wl-paste, xclip -o, xsel -o. So a paste asks them, and what comes back is what
 * any other program would paste - not just what this one copied.
 *
 * OSC 52 could ask the TERMINAL to send the clipboard, but the reply is even
 * less reliable than the write: most terminals refuse a clipboard READ outright,
 * as an obvious way for a remote program to steal what you copied. When the
 * terminal DOES paste - the user pressing its own paste key - it arrives as a
 * bracketed paste and this is not consulted at all.
 *
 * Writes up to `cap` bytes into `out`, returns how many, or 0 when no helper is
 * installed or the clipboard is empty. The child's stdin is /dev/null and its
 * stderr is too, so it can neither read a key meant for this program nor draw on
 * the screen it is using.
 */
size_t paste_extern(char *out, size_t cap)
{
	static const char *const helper[][4] = {
		{ "wl-paste", "-n", NULL, NULL },
		{ "xclip", "-o", "-selection", "clipboard" },
		{ "xsel", "-o", "-b", NULL }
	};
	size_t h;

	for (h = 0; h < sizeof helper / sizeof helper[0]; h++) {
		int fds[2];
		pid_t pid;
		int status = 0;
		size_t got = 0;

		if (pipe(fds) != 0)
			return 0;
		pid = fork();
		if (pid < 0) {
			close(fds[0]);
			close(fds[1]);
			return 0;
		}
		if (pid == 0) {
			int devnull = open("/dev/null", O_RDWR);

			if (devnull >= 0) {
				dup2(devnull, STDIN_FILENO);
				dup2(devnull, STDERR_FILENO);
			}
			dup2(fds[1], STDOUT_FILENO);
			close(fds[0]);
			close(fds[1]);
			{
				char *argv[4];
				size_t a;

				for (a = 0; a < 4u; a++)
					argv[a] = helper[h][a]
						  ? strdup(helper[h][a]) : NULL;
				execvp(argv[0], argv);
			}
			_exit(127);
		}
		close(fds[1]);
		while (got < cap) {
			ssize_t r = read(fds[0], out + got, cap - got);

			if (r <= 0)
				break;
			got += (size_t)r;
		}
		close(fds[0]);
		if (waitpid(pid, &status, 0) == pid &&
		    WIFEXITED(status) && WEXITSTATUS(status) == 0 && got)
			return got;
		/* Installed but empty, or not installed (exit 127): try the
		 * next tool rather than returning an empty clipboard as final. */
	}
	return 0;
}

#endif /* _WIN32 */

void copy_osc52(const char *bytes, size_t n)
{
	static const char b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
				  "abcdefghijklmnopqrstuvwxyz0123456789+/";
	struct out o = { 0 };
	size_t i;

	out_str(&o, "\033]52;c;");
	for (i = 0; i < n; i += 3) {
		unsigned long w = (unsigned long)(unsigned char)bytes[i] << 16;
		char t[5];

		if (i + 1 < n)
			w |= (unsigned long)(unsigned char)bytes[i + 1] << 8;
		if (i + 2 < n)
			w |= (unsigned long)(unsigned char)bytes[i + 2];
		t[0] = b64[(w >> 18) & 63];
		t[1] = b64[(w >> 12) & 63];
		t[2] = i + 1 < n ? b64[(w >> 6) & 63] : '=';
		t[3] = i + 2 < n ? b64[w & 63] : '=';
		t[4] = 0;
		out_str(&o, t);
	}
	out_str(&o, "\a");
	if (o.n)
		term_write_n(o.p, o.n);
	free(o.p);
	copy_take(bytes, n);
	g_clip_via = copy_extern(bytes, n);
}

/*
 * The picked lines, into the clipboard.
 *
 * Its own function rather than a branch of menu_run, because the keyboard
 * reaches it too and menu_run answers a question the keyboard has not asked:
 * whether the item is SHOWN, which depends on a menu being open. Routing Ctrl+C
 * through it copied nothing at all - the menu context is zero when no menu is
 * up - and the failure was silent, which is the worst kind for a copy.
 */
void dis_copy(struct view *v)
{
	struct out d = { 0 };
	int r, rows = 0;

	/*
	 * Either kind of selection will do.
	 *
	 * dis_have is the panel's OWN text selection. Requiring it here is what
	 * made Copy silent on a range picked in the hex pane: the rows were lit,
	 * the menu offered Copy, and this returned before looking at a single
	 * one of them.
	 */
	if (!v->dis_open || v->dis_lines <= 0 ||
	    (!v->dis_have && !dis_hex_sel(v)))
		return;

	/*
	 * A SELECTION SPANNING MORE THAN ONE INSTRUCTION IS COPIED WHOLE, not
	 * only where it shows.
	 *
	 * The panel is a window - it decodes as many instructions as it has rows
	 * and no more - but a selection can be longer than that window, whether it
	 * was made in the hex pane or dragged down the disassembly itself while it
	 * scrolled. Copying only the visible rows cut the clipboard off at whatever
	 * happened to be on screen, so a reader who selected a whole region and
	 * copied got the top of it and silently lost the rest. So the byte range is
	 * decoded here from its first instruction to its last, off the screen
	 * entirely.
	 *
	 * A SINGLE-INSTRUCTION disassembly selection stays row-based: there it IS
	 * the characters on the one row - part of a mnemonic, an operand on its own
	 * - and copying the whole instruction instead would put in the clipboard
	 * more than the reader can see they picked. dis_span's two ends being the
	 * same instruction is what tells the two apart.
	 */
	{
		uint64_t lo = 0, hi = 0;
		int whole = 0;

		if (!v->dis_have && dis_hex_sel(v)) {
			lo = v->sel_a < v->sel_b ? v->sel_a : v->sel_b;
			hi = v->sel_a < v->sel_b ? v->sel_b : v->sel_a;
			whole = 1;
		} else if (v->dis_have) {
			uint64_t a0, a1;
			int c0, c1;

			dis_span(v, &a0, &c0, &a1, &c1);
			if (a0 != a1) {         /* more than one instruction */
				lo = a0;
				hi = a1;        /* the loop takes the a1 one whole */
				whole = 1;
			}
		}

		if (whole) {
			uint64_t at = dis_sync(v, lo);
			uint32_t guard = 0;

			while (at <= hi && at < v->rgn_len &&
			       guard++ < (1u << 20)) {
				char line[120];

				if (!dis_format(v, &at, line, sizeof line,
						NULL, NULL, NULL, NULL, 0))
					break;
				if (rows)
					out_str(&d, "\n");
				out_add(&d, line, strlen(line));
				rows++;
			}
		} else
		for (r = 0; r < v->dis_lines; r++) {
			int len = (int)strlen(v->dis_line[r]);
			int from, to;

			if (!dis_cols(v, v->dis_line_at[r], v->dis_line_len[r],
				      len, &from, &to))
				continue;
			if (to <= from)
				continue;
			if (rows)
				out_str(&d, "\n");
			out_add(&d, v->dis_line[r] + from, (size_t)(to - from));
			rows++;
		}
	}
	if (d.n) {
		copy_osc52(d.p, d.n);
		snprintf(v->act_msg, sizeof v->act_msg, "Copied %d line(s)",
			 rows);
		v->act_ok = 1;
	}
	free(d.p);
}


/*
 * Say where the bytes went.
 *
 * A copy that reports nothing cannot be told from a copy that did nothing, and
 * this one really does fail on the common terminals - so the difference has to
 * be on the screen. Naming the helper when one took it is not decoration: it is
 * how the next person knows whether the clipboard they are about to paste from
 * has been written at all.
 */
void copy_said(struct view *v, size_t n)
{
	v->act_ok = g_clip_via != NULL;
	if (g_clip_via)
		snprintf(v->act_msg, sizeof v->act_msg,
			 "Copied %u byte(s) via %s", (unsigned)n, g_clip_via);
	else
		snprintf(v->act_msg, sizeof v->act_msg,
			 "Copied %u byte(s); terminal refused clipboard", (unsigned)n);
}

/* Copying an offset is copying a number, so it has two spellings and both are
 * worth having: hex to paste back into this tool, decimal for anything that
 * counts bytes. */
void copy_offset(struct view *v, int hex)
{
	char t[32];

	snprintf(t, sizeof t, hex ? "%llx" : "%llu",
		 (unsigned long long)v->menu_off);
	copy_osc52(t, strlen(t));
	copy_said(v, strlen(t));
}

/*
 * THE BYTE SELECTION, ONTO THE CLIPBOARD.
 *
 * Its own function because two things ask for it and one of them is not a menu
 * item. Ctrl+C went through menu_run, which opens with a menu_enabled test -
 * and that test asks whether the item is in the CONTEXT MENU THAT IS OPEN.
 * With no menu open the context is whatever a previous right-click left behind,
 * so the chord did nothing at all and did it silently.
 *
 * The gate belongs to the menu, not to the copy.
 */
void copy_selection(struct view *v, int as_hex)
{
	uint64_t lo, hi, k, n, bn = 0;
	const uint8_t *bp;
	struct out t = { 0 };

	if (v->sel_a == KGENOME_BROKEN || v->sel_b == KGENOME_BROKEN)
		return;
	lo = v->sel_a < v->sel_b ? v->sel_a : v->sel_b;
	hi = v->sel_a < v->sel_b ? v->sel_b : v->sel_a;
	n = hi - lo + 1u;
	bp = view_bytes(v, &bn);

	for (k = 0; k < n; k++) {
		uint64_t bf = view_map(v, lo + k, 0);
		uint8_t c = (bp && bf < bn) ? bp[bf] : 0;

		if (as_hex) {
			char x[3];

			snprintf(x, sizeof x, "%02X", c);
			out_add(&t, x, 2);
		} else {
			/* The bytes as they are, not as they print. A marker is
			 * bytes, and turning the unprintable ones into dots
			 * would put something in the clipboard that is not what
			 * was selected. */
			out_add(&t, (const char *)&c, 1);
		}
	}
	if (t.n) {
		copy_osc52(t.p, t.n);
		copy_said(v, t.n);
	}
	free(t.p);
}
