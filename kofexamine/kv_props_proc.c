#define _GNU_SOURCE

/*
 * kv_props_proc.c - the Process page of the properties: environment, connections,
 * open descriptors and mapped libraries, each a table of the table renderer (proc_table). Split from
 * kv_props.c by what is described (a live process), no logic changed.
 */

#include "kv_props_private.h"

/* memchr and not strchr, so the separator may be NUL - see prop_list.len. */
static const char *plist_nth(const char *t, uint32_t tn, char sep, uint32_t n,
			     char *out, size_t cap)
{
	uint32_t i = 0, at = 0;

	out[0] = 0;
	while (at < tn) {
		const char *e = memchr(t + at, sep, tn - at);
		size_t len = e ? (size_t)(e - (t + at)) : (size_t)(tn - at);

		if (i == n) {
			if (len >= cap)
				len = cap ? cap - 1u : 0u;
			memcpy(out, t + at, len);
			out[len] = 0;
			return out;
		}
		i++;
		if (!e)
			break;
		at = (uint32_t)(e - t) + 1u;
	}
	return out;
}

static uint32_t plist_count(const char *t, uint32_t tn, char sep)
{
	uint32_t n = 0, at = 0;

	while (at < tn) {
		const char *e = memchr(t + at, sep, tn - at);

		n++;
		if (!e)
			break;
		at = (uint32_t)(e - t) + 1u;
	}
	return n;
}

/* The block's extent - what the caller declared, or strlen when it did not. */
static uint32_t plist_len(const struct prop_list *l)
{
	return l->len ? l->len : (uint32_t)strlen(l->text);
}

/* NAME=value split into two columns - the whole reason the environment is a
 * table and not a list: the names line up, so the eye finds LD_PRELOAD without
 * reading a single value. */
static void env_cell(void *user, uint32_t row, const char **out)
{
	struct prop_list *l = user;
	char *eq;

	plist_nth(l->text, plist_len(l), l->sep, row, l->buf[0],
		  sizeof l->buf[0]);
	eq = strchr(l->buf[0], '=');
	if (eq) {
		*eq = 0;
		snprintf(l->buf[1], sizeof l->buf[1], "%s", eq + 1);
	} else {
		l->buf[1][0] = 0;
	}
	out[0] = l->buf[0];
	out[1] = l->buf[1];
}

/* "TCP 1.2.3.4:1 -> 5.6.7.8:2 STATE" into four columns. */
static void net_cell(void *user, uint32_t row, const char **out)
{
	struct prop_list *l = user;
	char raw[256];

	plist_nth(l->text, plist_len(l), l->sep, row, raw, sizeof raw);
	l->buf[0][0] = l->buf[1][0] = l->buf[2][0] = l->buf[3][0] = 0;
	if (sscanf(raw, "%15s %63s -> %63s %31s", l->buf[0], l->buf[1],
		   l->buf[2], l->buf[3]) < 3)
		snprintf(l->buf[0], sizeof l->buf[0], "%s", raw);
	out[0] = l->buf[0];
	out[1] = l->buf[1];
	out[2] = l->buf[2];
	out[3] = l->buf[3];
}

static void fd_cell(void *user, uint32_t row, const char **out)
{
	static const char *const names[3] = { "stdin", "stdout", "stderr" };
	struct prop_fdlist *f = user;
	uint32_t off = f->pi->off_fd0, k;
	const char *t = "";

	for (k = 0; k <= row && k < 3u; k++) {
		t = prop_proc_str(f->ob, off);
		if (!off || off >= f->ob->buf.n)
			break;
		off += (uint32_t)strlen(t) + 1u;
	}
	snprintf(f->buf, sizeof f->buf, "%s", t[0] ? t : "(none)");
	out[0] = names[row < 3u ? row : 2u];
	out[1] = f->buf;
}

/* A process table: measured widths, the last column takes the room the dialog leaves, no row count - the rows are page lines
 * and the page scrolls. */
static void proc_table(struct view *v, const char *head, const struct prop_col *c, uint32_t n_col, uint32_t n_sticky,
		       uint32_t n_row, void (*cell)(void *, uint32_t, const char **), void *user)
{
	struct kv_tab_spec t;

	prop_spec(&t, c, n_col, n_row, n_sticky, (int)n_col - 1, cell, user);
	kv_tab_measure(&t);
	prop_head(head);
	prop_table(v, &t);
}

static void prop_proc_libs(struct view *v);

void prop_proc(struct view *v, const struct object *ob)
{
	const struct kof_proc_info *pi = ob->info;
	const char *cmd;

	if (!pi || !pi->valid)
		return;

	prop_head("Process");
	prop_add(A_DIM "  %-11s " A_SIZE "%lu" A_OFF A_DIM "  parent " A_OFF
		 A_SIZE "%lu" A_OFF, "pid", (unsigned long)pi->pid,
		 (unsigned long)pi->ppid);
	prop_add(A_DIM "  %-11s " A_ID "%s" A_OFF, "exe",
		 prop_proc_str(ob, pi->off_exe));
	prop_add(A_DIM "  %-11s " A_ID "%s" A_OFF, "name",
		 prop_proc_str(ob, pi->off_comm));
	cmd = prop_proc_str(ob, pi->off_cmdline);
	/*
	 * SAID EVEN WHEN IT IS EMPTY, because an empty command line and one
	 * nobody could read are different facts and only one of them is about
	 * the program - the same distinction KOFW_PF_CMDLINE_LOST draws.
	 */
	prop_add(A_DIM "  %-11s " A_ID "%s" A_OFF, "cmdline",
		 cmd[0] ? cmd : "(none recorded)");

	/*
	 * The per-platform tail, named by the record's OWN os rather than by
	 * this build: a snapshot taken on the other platform reads correctly
	 * here, which is the reason kof_proc_rec carries the byte at all.
	 */
	if (pi->os == KOF_PLAT_WINDOWS)
		prop_add(A_DIM "  %-11s " A_SIZE "%lu" A_OFF A_DIM
			 "  integrity " A_OFF A_SIZE "%lu" A_OFF, "session",
			 (unsigned long)pi->plat_a,
			 (unsigned long)pi->plat_b);
	else
		prop_add(A_DIM "  %-11s " A_SIZE "%lu" A_OFF A_DIM "  gid "
			 A_OFF A_SIZE "%lu" A_OFF, "uid",
			 (unsigned long)pi->plat_a,
			 (unsigned long)pi->plat_b);

	/*
	 * THE COUNTS, AND WHETHER THEY WERE READ AT ALL.
	 *
	 * KOF_PROC_F_FDS_READ is what separates "this process holds no
	 * descriptors" from "nobody was allowed to look", and a panel that
	 * printed 0 for both would be inventing the first.
	 */
	if (pi->flags & KOF_PROC_F_FDS_READ)
		prop_add(A_DIM "  %-11s " A_SIZE "%lu" A_OFF A_DIM
			 "  sockets " A_OFF A_SIZE "%lu" A_OFF, "fds",
			 (unsigned long)pi->n_fd,
			 (unsigned long)pi->n_socket);
	else
		prop_add(A_DIM "  %-11s not readable" A_OFF, "fds");

	/*
	 * WHAT WAS NOT COLLECTED, WHERE THE THINGS THAT WERE ARE LISTED.
	 *
	 * The tables below are a list of what this process has, and a list
	 * that quietly stops is read as the whole of it. Saying the number
	 * here turns "these are its mappings" into "these are the ones that
	 * were taken", which is the true statement and the one a reader needs
	 * before concluding a library is absent.
	 */
	if (v->proc_skipped)
		prop_add(A_WARN "  %-11s %lu mapping(s) not collected" A_OFF
			 A_DIM " - too large, or past the time this may take"
			 A_OFF, "partial", (unsigned long)v->proc_skipped);

	/*
	 * The three shapes the rules key on, said in words. A reader looking
	 * at a panel should be able to see what a rule saw.
	 *
	 * STILL IN THE PROCESS SECTION, above the tables: each table now has a
	 * heading of its own, so a row left after them reads as a footnote to
	 * whichever one it happens to follow.
	 */
	if (pi->fd_same_01)
		prop_add(A_WARN "  %-11s fd 0 and fd 1 name the SAME object"
			 A_OFF, "stdio");
	if (pi->comm_bracketed)
		prop_add(A_WARN "  %-11s name is bracketed, like a kernel "
			 "thread" A_OFF, "masquerade");
	if (pi->flags & KOF_PROC_F_KTHREAD)
		prop_add(A_DIM "  %-11s kernel thread" A_OFF, "kind");
	if (!(pi->flags & KOF_PROC_F_EXE_ON_DISK))
		prop_add(A_WARN "  %-11s the executable is not on disk" A_OFF,
			 "exe");

	/*
	 * WHAT IT HAS MAPPED, FIRST.
	 *
	 * The order here is the order a reader asks in: what is this running,
	 * who is it talking to, what does it hold open, and how was it
	 * launched. The mapped files answer the first and are the widest net -
	 * a library nobody shipped is visible here and nowhere else in the
	 * panel.
	 */
	prop_proc_libs(v);

	/*
	 * WHO IT IS TALKING TO. Beside the descriptors and not on a page of
	 * its own, because the two answer one question together: a socket on
	 * fd 0 is a reverse shell only once you know what it is CONNECTED TO.
	 */
	{
		static const struct prop_col col[] = {
			{ "proto", 0, 0, A_ID }, { "local", 0, 0, A_LOC }, { "remote", 0, 0, A_S_NAME }, { "state", 0, 0, A_WARN }
		};
		struct prop_list nl;
		const char *raw = prop_proc_str(ob, pi->off_net);

		if (raw[0]) {
			memset(&nl, 0, sizeof nl);
			nl.text = raw;
			nl.sep = '\n';
			proc_table(v, "Connections", col, 4, 1, plist_count(raw, (uint32_t)strlen(raw), '\n'), net_cell, &nl);
		} else if (pi->n_socket) {
			/*
			 * SOCKETS IT HOLDS AND NOTHING TO SAY ABOUT THEM -
			 * a unix socket, or a namespace this could not read.
			 * The count beats a blank that reads as "none".
			 */
			prop_head("Connections");
			prop_add(A_DIM "  %lu socket(s), none in the "
				 "connection tables" A_OFF,
				 (unsigned long)pi->n_socket);
		}
	}

	/*
	 * THE DESCRIPTORS, through the same table - see proc_table.
	 *
	 * They are read ACROSS rather than down: the question is never "what
	 * is fd 1" on its own, it is whether two of them name the same thing.
	 * Three rows in one column makes a reader hold two strings in their
	 * head; a table puts them under each other where the eye does it.
	 *
	 * Three rows is under the framing threshold, so it draws as a plain
	 * heading and three rows - a border round three values is furniture.
	 * The threshold is the table's, not this caller's: the day the record
	 * carries every descriptor rather than the standard three, the frame
	 * and the scroll appear on their own.
	 */
	{
		static const struct prop_col col[] = { { "stream", 0, 0, A_ID }, { "target", 0, 0, A_S_NAME } };
		struct prop_fdlist fl;

		fl.ob = ob;
		fl.pi = pi;
		proc_table(v, "Descriptors", col, 2, 1, 3, fd_cell, &fl);
	}

	/*
	 * THE ENVIRONMENT AND THE CONNECTIONS, both as tables with a scroll of
	 * their own - see proc_table for why they are declared rather
	 * than drawn here.
	 */
	{
		static const struct prop_col col[] = { { "variable", 0, 0, A_ID }, { "value", 0, 0, A_S_NAME } };
		struct prop_list el;
		uint32_t en = pi->len_env;

		memset(&el, 0, sizeof el);
		el.text = prop_proc_str(ob, pi->off_env);
		/*
		 * NUL-SEPARATED, AND THE EXTENT IS THE REGION'S. The arena
		 * writes a terminator after the block, and the region runs to
		 * the next one's offset, so the last byte or two are NULs that
		 * would each read as an empty variable.
		 */
		while (en && !el.text[en - 1u])
			en--;
		el.len = en;
		el.sep = '\0';
		if (en)
			proc_table(v, "Environment", col, 2, 1, plist_count(el.text, en, '\0'), env_cell, &el);
	}
}

/*
 * The nth object that IS a mapped file.
 *
 * `proc_path` is the test and the only one needed: the walk stamps it on the
 * object it made from a mapped file and on nothing else, so this excludes the
 * memory regions (MEM_HEAP and its kind, which have no file behind them) and
 * the CHILDREN of a mapped file - an appended payload, an archive member -
 * which are things found INSIDE a mapping rather than mappings.
 *
 * Walked per row rather than indexed once, because the list is bounded by
 * PROC_SEEN_MAX and a table shows twenty rows.
 */
static uint32_t lib_obj(const struct view *v, uint32_t row)
{
	uint32_t i, n = 0;

	for (i = 1; i < v->n_obj; i++) {
		if (!v->obj[i].proc_path)
			continue;
		if (n++ == row)
			return i;
	}
	return 0;
}

static uint32_t lib_count(const struct view *v)
{
	uint32_t i, n = 0;

	for (i = 1; i < v->n_obj; i++)
		if (v->obj[i].proc_path)
			n++;
	return n;
}

static void lib_cell(void *user, uint32_t row, const char **out)
{
	struct prop_liblist *l = user;
	uint32_t i = lib_obj(l->v, row);
	const struct object *o;

	l->buf[0][0] = l->buf[1][0] = l->buf[2][0] = 0;
	if (!i) {
		out[0] = out[1] = out[2] = "";
		return;
	}
	o = &l->v->obj[i];
	if (o->fmt)
		snprintf(l->buf[0], sizeof l->buf[0], "%s-%s",
			 kof_format_name(o->ctx.format),
			 kof_arch_name(o->ctx.arch));
	else
		snprintf(l->buf[0], sizeof l->buf[0], "data");
	snprintf(l->buf[1], sizeof l->buf[1], "%llu",
		 (unsigned long long)o->buf.n);
	/* Every row here has a path - it is what put the row in the table. */
	snprintf(l->buf[2], sizeof l->buf[2], "%s",
		 l->v->seen_path[o->proc_path - 1u]);
	out[0] = l->buf[0];
	out[1] = l->buf[1];
	out[2] = l->buf[2];
}

static void prop_proc_libs(struct view *v)
{
	static const struct prop_col col[] = { { "type", 0, 0, A_ID }, { "bytes", 0, 1, A_SIZE }, { "path", 0, 0, A_S_NAME } };
	struct prop_liblist ll;

	if (!v->n_obj)
		return;
	ll.v = v;
	proc_table(v, "Mapped files", col, 3, 2, lib_count(v), lib_cell, &ll);
}
