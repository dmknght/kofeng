/*
 * kofevtfmt.c - see kofevtfmt.h.
 *
 * Moved out of kofwinmon/wrender.c. Nothing here knows about ETW, a provider
 * or a session: it renders a struct kof_evt, so the same code prints a live
 * Windows session and a log replayed on Linux. That is the property that makes
 * a recorded log worth keeping - a line that only one build can produce is not
 * evidence anybody else can read.
 */

#include <string.h>

#include "kofevtfmt.h"

/*
 * SANITISED HERE, BECAUSE THIS IS WHERE THE TERMINAL IS.
 *
 * The record carries content raw - see kofevt.h - precisely so the half that
 * scans it gets what arrived. A printer has the opposite duty: the bytes were
 * chosen by whoever wrote the script, they are about to go to a terminal, and
 * an escape sequence among them is a report that lies about what it says.
 *
 * So the conversion happens at the last possible moment and nowhere earlier.
 * Control characters and anything above printable ASCII become '.', and the
 * length is the CONTENT's rather than a NUL's, because content may hold NULs.
 */
static void print_sanitised(FILE *out, const char *p, size_t n, size_t cap)
{
	size_t i;

	if (n > cap)
		n = cap;
	for (i = 0; i < n; i++) {
		unsigned char c = (unsigned char)p[i];

		fputc((c >= 0x20u && c < 0x7fu) ? (int)c : '.', out);
	}
}

void kof_evt_count(const struct kof_evt *e, struct kof_evt_tally *t)
{
	switch (e->verb) {
	case KOF_EVT_PROC_START:     t->proc++;     break;
	case KOF_EVT_IMAGE_LOAD:     t->image++;    break;
	case KOF_EVT_FILE_NEW:       t->file_new++; break;
	case KOF_EVT_FILE_DELETE:    t->file_del++; break;
	case KOF_EVT_FILE_RENAME:    t->file_ren++; break;
	case KOF_EVT_FILE_WRITE:     t->file_wr++;  break;
	case KOF_EVT_REG_CREATE:
	case KOF_EVT_REG_SET_VALUE:
	case KOF_EVT_REG_DELETE:     t->reg++;      break;
	case KOF_EVT_NET_CONNECT:    t->conn++;     break;
	case KOF_EVT_NET_SEND:       t->bytes_sent += e->net_size; break;
	case KOF_EVT_NET_RECV:       t->bytes_recv += e->net_size; break;
	case KOF_EVT_PROC_STOP:
	case KOF_EVT_IMAGE_UNLOAD:
	case KOF_EVT_NET_DISCONNECT:
	case KOF_EVT_THREAD_START:   t->thread++;   break;
	case KOF_EVT_THREAD_STOP:                   break;
	case KOF_EVT_AMSI_SCAN:      t->amsi++;     break;
	default:                      t->raw++;      break;
	}
}

void kof_evt_render(const struct kof_evt *e, double secs, const char *who,
		    FILE *out, struct kof_evt_tally *t)
{
	kof_evt_count(e, t);

	fprintf(out, "%8.3f  %-9s pid=%-6lu %-20s", secs,
	       kof_evt_verb_name(e->verb), (unsigned long)e->pid,
	       who && *who ? who : "?");

	switch (e->verb) {
	case KOF_EVT_PROC_START: {
		const char *cl = kof_evt_cmdline(e);

		fprintf(out, "  ppid=%lu  %s", (unsigned long)e->ppid,
		       kof_evt_image(e));
		/*
		 * On its own line and indented, because it is usually longer
		 * than everything before it and because it is the line that
		 * matters. An image path names the program; the arguments name
		 * what it was asked to do, and for every living-off-the-land
		 * technique the second IS the event.
		 */
		if (*cl)
			fprintf(out, "\n                                 cmd: %s",
			       cl);
		else if (e->flags & KOF_EF_CMDLINE_RACED)
			fprintf(out, "  [cmd unread: process gone]");
		break;
	}
	case KOF_EVT_PROC_STOP:
		fprintf(out, "  exit=%lu", (unsigned long)e->exit_code);
		break;
	case KOF_EVT_IMAGE_LOAD:
		fprintf(out, "  [%s] %s", kof_loc_name(e->loc),
		       kof_evt_object(e));
		break;
	case KOF_EVT_IMAGE_UNLOAD:
		fprintf(out, "  [%s] %s", kof_loc_name(e->loc),
		       kof_evt_object(e));
		break;
	/* Unreachable until type_of() learns the ids - kept so that typing
	 * them is a one-line change there and not two. */
	case KOF_EVT_THREAD_START:
	case KOF_EVT_THREAD_STOP:
		fprintf(out, "  start=0x%llx", (unsigned long long)e->addr);
		break;
	case KOF_EVT_AMSI_SCAN: {
		/*
		 * The submitted content, RAW in the record and sanitised here.
		 *
		 * It is also a PREFIX: unlike a path, a script block is usually
		 * longer than the arena, so the [cut] marker the common tail
		 * adds is doing real work - most of these are legitimately
		 * incomplete rather than exceptionally so.
		 *
		 * Printed through print_sanitised and not with %s, for two
		 * reasons that are both the point of content_len existing: the
		 * bytes may contain NULs, so %s would stop at the first one;
		 * and they may contain a terminal escape, which %s would send
		 * to the terminal.
		 */
		const char *ct = NULL;
		size_t cn = 0;

		if (kof_evt_content(e, &ct, &cn) && cn) {
			fputs("  ", out);
			print_sanitised(out, ct, cn, 120u);
			if (cn > 120u)
				fprintf(out, "... (%llu bytes)",
					(unsigned long long)cn);
		} else {
			fputs("  (no content)", out);
		}
		break;
	}
	case KOF_EVT_FILE_NEW:
		fprintf(out, "  [%s] %s", kof_loc_name(e->loc),
		       kof_evt_object(e));
		break;
	case KOF_EVT_FILE_DELETE:
		fprintf(out, "  [%s] %s", kof_loc_name(e->loc),
		       kof_evt_object(e));
		break;
	case KOF_EVT_FILE_RENAME:
		fprintf(out, "  [%s] %s", kof_loc_name(e->loc),
		       kof_evt_object(e));
		break;
	case KOF_EVT_FILE_WRITE:
		fprintf(out, "  [%s] %s", kof_loc_name(e->loc),
		       kof_evt_object(e));
		if (e->net_size)
			fprintf(out, "  %lu bytes", (unsigned long)e->net_size);
		break;

	/*
	 * The registry path goes in the same column every other object path
	 * goes in, so a reader scanning for "what did it touch" reads one
	 * column rather than learning where each provider hides its answer.
	 */
	case KOF_EVT_REG_CREATE:
	case KOF_EVT_REG_SET_VALUE:
	case KOF_EVT_REG_DELETE:
		fprintf(out, "  %s", kof_evt_object(e));
		break;

	case KOF_EVT_NET_CONNECT:
	case KOF_EVT_NET_DISCONNECT:
	case KOF_EVT_NET_SEND:
	case KOF_EVT_NET_RECV: {
		/*
		 * The address arrives as four bytes in the order they sit in the
		 * packet and the port in network byte order. Swapped here rather
		 * than in the record, for the reason kofw_evt gives: a record
		 * that silently disagreed with the packet would be worse than
		 * one a printer has to swap.
		 */
		uint32_t d  = e->net_daddr;
		uint16_t dp = (uint16_t)((e->net_dport >> 8) |
					 (e->net_dport << 8));

		fprintf(out, "  %lu.%lu.%lu.%lu:%u",
		       (unsigned long)(d & 0xffu),
		       (unsigned long)((d >> 8) & 0xffu),
		       (unsigned long)((d >> 16) & 0xffu),
		       (unsigned long)((d >> 24) & 0xffu), (unsigned)dp);
		if (e->net_size)
			fprintf(out, "  %lu bytes", (unsigned long)e->net_size);
		break;
	}

	default:
		fprintf(out, "  [id %u]", (unsigned)e->raw_id);
		/*
		 * THE ADDRESS, ON THE RAW PATH TOO, and this was the bug.
		 *
		 * Thread events are not typed yet, so they arrive as RAW and
		 * render here - and this branch printed only the object path,
		 * which a thread event does not have. So `--thread` collected
		 * the one field it exists for and then showed an empty line.
		 * A start address that is never displayed is a subscription
		 * paying full volume for nothing.
		 */
		if (e->addr)
			fprintf(out, "  addr=0x%llx", (unsigned long long)e->addr);
		if (*kof_evt_object(e))
			fprintf(out, "  %s", kof_evt_object(e));
		break;
	}

	/*
	 * THE TECHNIQUE IS NOT PRINTED AT ALL, and that is the decision rather
	 * than an omission.
	 *
	 * It was rendered beside the path and it read as a verdict, which it
	 * is not: writing a Run value is what every installer on the machine
	 * does. Softening it to a name in braces was still wrong - anything on
	 * an event line is read as something that happened, and what happened
	 * was a registry write.
	 *
	 * The tag stays ON THE RECORD, because a rule will want it: it is a
	 * cheap fact, already computed, that a rule can require alongside the
	 * ones carrying the actual weight - who wrote it, what they wrote,
	 * what else they did in the same window. When that engine exists it
	 * will emit a FINDING line, and a technique id belongs there, where it
	 * names a decision somebody made rather than a directory somebody
	 * wrote to.
	 *
	 * Until then the line carries evidence and nothing else.
	 */

	/*
	 * Loud, because it is the only line in a trace that is a CONCLUSION
	 * rather than a report, and because it is the one thing in the whole
	 * stream that a reflectively loaded payload cannot avoid producing.
	 */
	if (e->flags & KOF_EF_UNBACKED)
		fprintf(out, "  <<UNBACKED: entry point in no mapped image>>");
	/* Quieter than UNBACKED on purpose: this one is common and legitimate,
	 * and a marker as loud would train a reader to ignore both. */
	if (e->flags & KOF_EF_LATE_LOAD)
		fprintf(out, "  [late]");

	if (e->flags & KOF_EF_TRUNCATED)
		fprintf(out, "  [cut]");
	/* Printed, never hidden: a field the decode could not supply is the
	 * difference between a fact and a zero. */
	if (e->flags & KOF_EF_PARTIAL)
		fprintf(out, "  [miss 0x%x]", (unsigned)e->miss);
	fputc('\n', out);
}

void kof_evt_print_tally(const struct kof_evt_tally *t, double secs,
			 const char *what, FILE *out)
{
	fprintf(out,
		"\n-- %.1fs, %s\n"
		"   processes started : %llu\n"
		"   modules loaded    : %llu\n"
		"   files created     : %llu\n"
		"   files deleted     : %llu\n"
		"   files renamed     : %llu\n"
		"   files written     : %llu\n"
		"   registry changes  : %llu\n"
		"   amsi submissions  : %llu\n"
		"   connections       : %llu\n"
		"   bytes sent/recv   : %llu / %llu\n"
		"   threads started   : %llu\n"
		"   untyped events    : %llu\n",
		secs, what,
		(unsigned long long)t->proc,
		(unsigned long long)t->image,
		(unsigned long long)t->file_new,
		(unsigned long long)t->file_del,
		(unsigned long long)t->file_ren,
		(unsigned long long)t->file_wr,
		(unsigned long long)t->reg,
		(unsigned long long)t->amsi,
		(unsigned long long)t->conn,
		(unsigned long long)t->bytes_sent,
		(unsigned long long)t->bytes_recv,
		(unsigned long long)t->thread,
		(unsigned long long)t->raw);
}


/* ------------------------------------------------- for a browsing UI */


/* The last component of a path or a registry key, so a label says which file
 * rather than which directory. Both separators, because one record may carry
 * either. */
static const char *tail_of(const char *p)
{
	const char *last = p;

	for (; *p; p++) {
		if (*p == '\\' || *p == '/')
			last = p + 1;
	}
	return last;
}

size_t kof_evt_label(const struct kof_evt *e, uint64_t index, char *out,
		     size_t cap)
{
	const char *obj;
	int n;

	if (!out || cap == 0)
		return 0;
	out[0] = '\0';
	if (!e)
		return 0;

	obj = kof_evt_object(e);
	if (!*obj)
		obj = kof_evt_image(e);

	/*
	 * The index first, because it is what a reader refers to and it sorts.
	 * Then the verb, then who, then the leaf of what - a full path does not
	 * fit a panel column and the directory is the part a reader can ask
	 * for separately.
	 */
	n = snprintf(out, cap, "//%llu %s pid=%lu%s%s",
		     (unsigned long long)index, kof_evt_verb_name(e->verb),
		     (unsigned long)e->pid, *obj ? " " : "",
		     *obj ? tail_of(obj) : "");
	if (n < 0)
		return 0;
	return ((size_t)n < cap) ? (size_t)n : cap - 1u;
}

/*
 * THE FIELD TABLE, and why it is a switch rather than a loop over a struct.
 *
 * Only the fields an event actually carries are worth a row, and which those
 * are depends on the verb: a file event has no ports, a thread start has no
 * exit code, and a row reading "dport 0" is worse than no row because a reader
 * cannot tell it from a real zero. So the order is fixed and the absent ones
 * are skipped, which means the index a caller passes is a position in what
 * THIS event has - not in some universal list.
 */
static int field_at(const struct kof_evt *e, unsigned want, unsigned *seen,
		    char *name, size_t ncap, char *val, size_t vcap)
{
#define ROW(nm, ...)                                                          \
	do {                                                                  \
		if (*seen == want) {                                          \
			snprintf(name, ncap, "%s", nm);                       \
			snprintf(val, vcap, __VA_ARGS__);                     \
			return 1;                                             \
		}                                                             \
		(*seen)++;                                                    \
	} while (0)

	ROW("verb",  "%s", kof_evt_verb_name(e->verb));
	ROW("pid",   "%lu", (unsigned long)e->pid);
	if (e->actor_pid && e->actor_pid != e->pid)
		ROW("actor", "%lu", (unsigned long)e->actor_pid);
	if (e->ppid)
		ROW("ppid",  "%lu", (unsigned long)e->ppid);
	if (e->tid)
		ROW("tid",   "%lu", (unsigned long)e->tid);
	ROW("stamp", "%llu", (unsigned long long)e->stamp);
	ROW("seq",   "%llu", (unsigned long long)e->seq);
	if (e->create_time)
		ROW("created", "%llu", (unsigned long long)e->create_time);
	if (e->session_id)
		ROW("session", "%lu", (unsigned long)e->session_id);
	if (e->verb == KOF_EVT_PROC_STOP)
		ROW("exit", "%lu", (unsigned long)e->exit_code);

	if (*kof_evt_image(e))
		ROW("image", "%s", kof_evt_image(e));
	if (*kof_evt_object(e))
		ROW("object", "%s", kof_evt_object(e));
	if (*kof_evt_cmdline(e))
		ROW("cmdline", "%s", kof_evt_cmdline(e));

	if (e->loc)
		ROW("where", "%s", kof_loc_name(e->loc));
	/*
	 * The technique, HERE and not on the event line - see the note in
	 * kofevt.h. A properties panel is somebody asking about one event on
	 * purpose, which is a different thing from a stream scrolling past.
	 */
	if (e->attack)
		ROW("technique", "%s %s", kof_attack_id(e->attack),
		    kof_attack_name(e->attack));

	if (e->net_daddr || e->net_dport) {
		uint32_t d = e->net_daddr;
		uint16_t dp = (uint16_t)((e->net_dport >> 8) |
					 (e->net_dport << 8));

		ROW("peer", "%lu.%lu.%lu.%lu:%u",
		    (unsigned long)(d & 0xffu),
		    (unsigned long)((d >> 8) & 0xffu),
		    (unsigned long)((d >> 16) & 0xffu),
		    (unsigned long)((d >> 24) & 0xffu), (unsigned)dp);
	}
	if (e->net_size)
		ROW("bytes", "%lu", (unsigned long)e->net_size);
	if (e->addr)
		ROW("addr", "0x%llx", (unsigned long long)e->addr);
	if (e->addr_size)
		ROW("addr size", "%llu", (unsigned long long)e->addr_size);
	if (e->raw_id)
		ROW("raw id", "%u", (unsigned)e->raw_id);
	ROW("source", "%s", (e->os & KOF_OS_WINDOWS) ? "windows" :
			    (e->os & KOF_OS_LINUX) ? "linux" : "unknown");

	/*
	 * The flags LAST and only when set, because each one qualifies
	 * everything above it: a truncated path, a field the collector could
	 * not supply, an entry point in no mapped image.
	 */
	if (e->flags & KOF_EF_TRUNCATED)
		ROW("note", "text was cut");
	if (e->flags & KOF_EF_PARTIAL)
		ROW("note", "fields missing (0x%x)", (unsigned)e->miss);
	if (e->flags & KOF_EF_UNBACKED)
		ROW("note", "entry point in no mapped image");
	if (e->flags & KOF_EF_LATE_LOAD)
		ROW("note", "module mapped long after process start");
	if (e->flags & KOF_EF_CMDLINE_RACED)
		ROW("note", "command line lost to the process exiting");
#undef ROW
	return 0;
}

int kof_evt_field(const struct kof_evt *e, unsigned i,
		  char *name, size_t ncap, char *val, size_t vcap)
{
	unsigned seen = 0;

	if (!e || !name || !val || ncap == 0 || vcap == 0)
		return 0;
	name[0] = val[0] = '\0';
	return field_at(e, i, &seen, name, ncap, val, vcap);
}

unsigned kof_evt_n_fields(const struct kof_evt *e)
{
	char n[32], v[64];
	unsigned i = 0;

	if (!e)
		return 0;
	while (kof_evt_field(e, i, n, sizeof n, v, sizeof v))
		i++;
	return i;
}

/* ----------------------------------------------- events that carry CONTENT */

int kof_evt_content(const struct kof_evt *e, const char **text, size_t *len)
{
	const char *t;

	if (!e)
		return 0;
	t = kof_evt_object(e);

	/*
	 * content_len AND NOT strlen, which is the whole reason the field
	 * exists: the content is raw bytes and may contain NULs - UTF-16 read
	 * as bytes has one at index 1 - so strlen would report exactly one
	 * character of a kilobyte submission.
	 */
	if (e->content_len) {
		if (text) *text = t;
		if (len)  *len  = e->content_len;
		return 1;
	}
	/* A verb that carries content but whose content did not arrive is
	 * still a content event; saying so lets a viewer show "empty" rather
	 * than showing a path column. */
	if (e->verb == KOF_EVT_AMSI_SCAN) {
		if (text) *text = t;
		if (len)  *len  = 0;
		return 1;
	}
	return 0;
}

int kof_evt_content_looks_binary(const struct kof_evt *e)
{
	const char *t = NULL;
	size_t n = 0, i, unknown = 0;

	if (!kof_evt_content(e, &t, &n) || n < 8)
		return 0;

	/*
	 * A HEURISTIC, AND LABELLED AS ONE.
	 *
	 * The collector already replaced every byte above 0x7f with '?' and
	 * every control character with '.', so what arrives here cannot be
	 * inspected as bytes - see the note in kofevtfmt.h. What it CAN be
	 * asked is whether the replacement characters dominate, which text
	 * does not do and a mangled binary does.
	 *
	 * "MZ" first is checked too, because that survives the conversion
	 * intact and is worth saying exactly rather than as a proportion.
	 */
	if (t[0] == 'M' && t[1] == 'Z')
		return 1;
	/*
	 * RAW BYTES NOW, so this asks the real question rather than counting
	 * replacement characters: how much of it is outside printable ASCII.
	 * Script text is almost all inside it; a PE, a UTF-16 buffer or a
	 * packed blob is not.
	 */
	for (i = 0; i < n; i++) {
		unsigned char c = (unsigned char)t[i];

		if (c < 0x09u || (c > 0x0du && c < 0x20u) || c >= 0x7fu)
			unknown++;
	}
	return unknown * 4u > n;
}
