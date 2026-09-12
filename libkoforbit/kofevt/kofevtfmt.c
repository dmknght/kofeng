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
	case KOF_EVT_NET_SEND:
	case KOF_EVT_NET_RECV: {
		const struct kof_evt_net *n = kof_evt_as_net(e);

		if (n) {
			if (e->verb == KOF_EVT_NET_SEND)
				t->bytes_sent += n->size;
			else
				t->bytes_recv += n->size;
		}
		break;
	}
	case KOF_EVT_PROC_STOP:
	case KOF_EVT_IMAGE_UNLOAD:
	case KOF_EVT_NET_DISCONNECT:
	case KOF_EVT_THREAD_START:   t->thread++;   break;
	case KOF_EVT_THREAD_STOP:                   break;
	case KOF_EVT_AMSI_SCAN:      t->amsi++;     break;
	case KOF_EVT_DNS_QUERY:      t->dns++;      break;
	/*
	 * A CONTINUATION IS NOT AN EVENT and is counted as nothing.
	 *
	 * It is the tail of the record in front of it - see KOF_EVT_CONT. Left
	 * to the default it would land in `raw`, and a tally would then report
	 * one AMSI submission as one amsi plus nine raws, which reads as ten
	 * things happening. Nine of them are the same thing.
	 */
	case KOF_EVT_CONT:                          break;
	default:                      t->raw++;      break;
	}
}

void kof_evt_render(const struct kof_evt *e, double secs, const char *who,
		    FILE *out, struct kof_evt_tally *t)
{
	kof_evt_count(e, t);

	/*
	 * A CONTINUATION IS NEVER PRINTED.
	 *
	 * It is the tail of the record in front of it, not an event - see
	 * KOF_EVT_CONT. Printed, it is a line saying "Cont pid=901" with a
	 * fragment of somebody else's script on it, repeated once per four
	 * hundred bytes: a submission split nine ways turned one event into ten
	 * lines, nine of which report nothing that happened.
	 *
	 * It is still COUNTED above - counted as nothing, which is what
	 * kof_evt_count does with it - so the tally stays right.
	 *
	 * The verb keeps its name because the writer needs one and a record
	 * whose verb printed as "?" would be a diagnostic problem of its own.
	 * What it does not need is a line of its own in a report; whoever wants
	 * the bytes joins them, and kof_evt_join is how.
	 */
	if (e->verb == KOF_EVT_CONT)
		return;

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
	case KOF_EVT_PROC_STOP: {
		const struct kof_evt_proc *pr = kof_evt_as_proc(e);

		if (pr)
			fprintf(out, "  exit=%lu", (unsigned long)pr->exit_code);
		break;
	}
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
	case KOF_EVT_THREAD_STOP: {
		const struct kof_evt_mem *m = kof_evt_as_mem(e);

		if (m)
			fprintf(out, "  start=0x%llx",
				(unsigned long long)m->addr);
		break;
	}
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
	case KOF_EVT_FILE_WRITE: {
		const struct kof_evt_file *f = kof_evt_as_file(e);

		fprintf(out, "  [%s] %s", kof_loc_name(e->loc),
		       kof_evt_object(e));
		/*
		 * THE RANGE AND NOT JUST THE LENGTH. "wrote 64 bytes to hosts"
		 * and "wrote 64 bytes at 0x1a2 in hosts" are a sentence and a
		 * piece of evidence respectively: only the second can be read
		 * back off the file afterwards, which is the whole reason
		 * kof_evt_file carries an offset.
		 */
		if (f && f->size)
			fprintf(out, "  %lu bytes @%llu", (unsigned long)f->size,
				(unsigned long long)f->offset);
		break;
	}

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
	case KOF_EVT_NET_RECV:
	case KOF_EVT_DNS_QUERY: {
		/*
		 * The address sits in the record in the order it sits in the
		 * packet and the port in network byte order. Turned into text
		 * here rather than stored that way, for the reason kofw_evt
		 * gives: a record that silently disagreed with the packet would
		 * be worse than one a printer has to convert.
		 *
		 * kof_evt_ip_str and not four %lu, because the same sixteen
		 * bytes have to come out as the same string here, in a report's
		 * IOC table and in a viewer - and a v6 address written by hand
		 * in three places is written three ways.
		 */
		const struct kof_evt_net *n = kof_evt_as_net(e);
		char  ip[KOF_IP_STR_MAX];
		uint16_t dp;

		if (!n)
			break;
		dp = (uint16_t)((n->dport >> 8) | (n->dport << 8));

		/*
		 * A LOOKUP PRINTS THE NAME IT ASKED ABOUT AND THEN THE ANSWER.
		 *
		 * The name is the object, which is why it is printed here and
		 * not by the address code below: for every other verb in this
		 * group the destination IS the subject of the line, and for
		 * this one the destination is the answer to it.
		 *
		 * An unset address is a lookup that FAILED, and that gets a
		 * word rather than a blank - a name that resolves to nothing is
		 * itself worth seeing, because it is what a domain-generation
		 * algorithm looks like while it is hunting for the one that is
		 * registered.
		 */
		if (e->verb == KOF_EVT_DNS_QUERY) {
			fprintf(out, "  %s", kof_evt_object(e));
			if (kof_evt_ip_is_unset(n->daddr))
				fputs("  -> no answer", out);
			else
				fprintf(out, "  -> %s",
					kof_evt_ip_str(n->daddr, ip, sizeof ip));
			break;
		}

		/* Brackets around a v6 address before the port, because
		 * 2001:db8::1:443 cannot be read and [2001:db8::1]:443 can. */
		kof_evt_ip_str(n->daddr, ip, sizeof ip);
		if (kof_evt_ip_is_v6(n->daddr))
			fprintf(out, "  [%s]:%u", ip, (unsigned)dp);
		else
			fprintf(out, "  %s:%u", ip, (unsigned)dp);
		if (n->size)
			fprintf(out, "  %lu bytes", (unsigned long)n->size);
		break;
	}

	default:
		/*
		 * "[file id 12]", not "[id 12]". A discovery run reads these
		 * lines to decide what to type, and an id without its provider
		 * is a number that names two different events.
		 */
		if (e->source)
			fprintf(out, "  [%s id %u]",
				kof_evt_source_name(e->source),
				(unsigned)e->raw_id);
		else
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
		{
			const struct kof_evt_mem *m = kof_evt_as_mem(e);

			if (m && m->addr)
				fprintf(out, "  addr=0x%llx",
					(unsigned long long)m->addr);
		}
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
		"   names looked up   : %llu\n"
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
		(unsigned long long)t->dns,
		(unsigned long long)t->conn,
		(unsigned long long)t->bytes_sent,
		(unsigned long long)t->bytes_recv,
		(unsigned long long)t->thread,
		(unsigned long long)t->raw);
}


/* ------------------------------------------------- for a browsing UI */



size_t kof_evt_label(const struct kof_evt *e, uint64_t index, char *out,
		     size_t cap)
{
	int n;

	if (!out || cap == 0)
		return 0;
	out[0] = '\0';
	if (!e)
		return 0;

	/*
	 * WHAT A ROW IN A LIST OF EVENTS HAS TO SAY, and no more.
	 *
	 * The index, the verb, the process. That is what a reader picks a row
	 * BY - the index to refer to it, the verb to find the kind they are
	 * after, the pid to follow one process through the log.
	 *
	 * It used to append the leaf of the path as well, which is the field a
	 * reader most wants and the one a list is worst at showing: it is the
	 * part that does not fit, so it is the part that gets truncated, and a
	 * column of half-cut filenames is a column that has to be read twice -
	 * once to guess and once in the panel that shows the whole record. The
	 * row's job is to get them to that panel, so it stops here.
	 *
	 * No "//" either. That was borrowed from the engine's nested-object
	 * naming, where it means "inside" - a section inside an executable, a
	 * member inside an archive. An event is not inside anything, and
	 * spelling it as though it were describes a structure the log does not
	 * have.
	 */
	n = snprintf(out, cap, "%llu %s pid=%lu",
		     (unsigned long long)index, kof_evt_verb_name(e->verb),
		     (unsigned long)e->pid);
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
/*
 * WHICH BYTES A ROW CAME FROM, alongside what it says.
 *
 * A panel showing a record's fields beside its bytes has to be able to light
 * up the ones a row is about - that is the whole value of showing them
 * together, and without it the two halves are two unrelated displays that
 * happen to share a screen.
 *
 * So every row declares its extent as well as its text, in the same macro, in
 * the same place. Kept together deliberately: an offset maintained in a second
 * table beside the formatting is an offset that drifts the first time somebody
 * adds a field, and the drift is invisible - a row lights up the wrong bytes
 * and looks exactly as correct as before.
 */
/*
 * HOW MANY BYTES OF THE OBJECT ARE ACTUALLY HERE.
 *
 * content_len is the length of what was SUBMITTED, and for an AMSI buffer that
 * is routinely kilobytes while the record's arena is four hundred bytes - so
 * the record holds a prefix and says so with KOF_EF_TRUNCATED. Used directly
 * as an extent it claimed bytes past the end of the record: a highlight that
 * ran off the field, over everything after it, and out of the struct.
 *
 * So it is clamped to what the arena actually contains. The full length is not
 * lost - it is what the reader is told in the value - but the RANGE has to be
 * the range that exists, because something is going to point at it.
 */
/*
 * A SUBMISSION AS A READER WANTS TO SEE IT, which is not byte for byte.
 *
 * The bytes are kept raw in the record on purpose - a scanner needs them - and
 * the first attempt at showing them wrote one character per byte, printable
 * ones as themselves and everything else as a dot. That is correct and it is
 * unreadable for the commonest case there is: a PowerShell script block
 * arrives as UTF-16, so every second byte is a NUL, and "IEX" came out as
 * "I.E.X." with a run of dots wherever the buffer was padded. A pane full of
 * dots is a pane that has to be decoded by eye before it can be read.
 *
 * So: if the buffer looks like UTF-16LE - a NUL above every character - the
 * high bytes are dropped and what is left is the text. Anything else is shown
 * byte for byte as before, because it might be a PE header and guessing at it
 * would be worse than dots.
 *
 * TRAILING NUL BYTES ARE CUT, and nothing else is.
 *
 * It used to cut every trailing unprintable, which is the same thing for a
 * padded string and a catastrophe for a PE: "MZ\x90\x00\x03\x00..." is
 * almost entirely unprintable, so the trim ate the whole image and left the
 * two letters. A reader would have seen "MZ" and had no way to tell a
 * two-byte submission from a hundred-kilobyte executable.
 *
 * A run of NULs at the end is padding in every case that produces one. A run
 * of anything else is data that happens not to be letters, and cutting it is
 * deciding on a reader's behalf that their payload was not worth showing.
 *
 * Returns how many characters were written; `out` is always terminated.
 */
static size_t content_readable(const char *p, size_t n, char *out, size_t cap);

int kof_evt_text_is_wide(const char *p, size_t n)
{
	size_t i;

	/* A single byte cannot be a UTF-16 unit. */
	if (!p || n < 2u)
		return 0;
	/*
	 * The test is over the whole buffer, not a sample: a PE section that
	 * begins with a few NUL-separated bytes would pass a sample and then be
	 * silently stripped of half of itself.
	 */
	for (i = 1; i < n; i += 2)
		if (p[i] != '\0')
			return 0;
	return 1;
}

size_t kof_evt_text_of(const char *p, size_t n, char *out, size_t cap)
{
	return content_readable(p, n, out, cap);
}

static size_t content_readable(const char *p, size_t n, char *out, size_t cap)
{
	size_t i, w = 0;
	int wide;

	if (!out || cap == 0)
		return 0;
	out[0] = '\0';
	if (!p || n == 0)
		return 0;

	/*
	 * The test is over the whole buffer, not a sample: a PE section that
	 * begins with a few NUL-separated bytes would pass a sample and then be
	 * silently stripped of half of itself. One pass costs nothing here -
	 * this runs per drawn row, not per event.
	 */
	/* Asked BEFORE the padding is cut: the test needs whole pairs, and
	 * trimming can leave an odd number of bytes. */
	wide = kof_evt_text_is_wide(p, n);

	/* The padding, which says nothing. Cut from the SOURCE rather than
	 * from the rendering, so it is the NUL bytes that go and not every
	 * byte that happened to render as a dot. */
	while (n && p[n - 1u] == '\0')
		n--;

	for (i = 0; i < n && w + 1u < cap; i += wide ? 2u : 1u) {
		unsigned char c = (unsigned char)p[i];

		out[w++] = (c >= 0x20u && c < 0x7fu) ? (char)c : '.';
	}
	out[w] = '\0';
	return w;
}

static uint16_t obj_extent(const struct kof_evt *e)
{
	size_t room, n;

	if (e->off_object == KOF_TEXT_NONE ||
	    e->off_object >= sizeof e->text)
		return 0;
	room = sizeof e->text - e->off_object;
	n = e->content_len ? e->content_len : strlen(kof_evt_object(e));
	/* The arena's own declared length bounds it too, when it is set: past
	 * text_len the bytes belong to no field at all. */
	if (e->text_len > e->off_object &&
	    (size_t)(e->text_len - e->off_object) < room)
		room = (size_t)(e->text_len - e->off_object);
	return (uint16_t)(n < room ? n : room);
}

static int field_at(const struct kof_evt *e, unsigned want, unsigned *seen,
		    char *name, size_t ncap, char *val, size_t vcap,
		    uint16_t *xoff, uint16_t *xlen)
{
#define AT(f)  (uint16_t)offsetof(struct kof_evt, f)
#define SZ(f)  (uint16_t)sizeof ((struct kof_evt *)0)->f
#define ROWX(nm, o, l, ...)                                                   \
	do {                                                                  \
		if (*seen == want) {                                          \
			if (name) snprintf(name, ncap, "%s", nm);             \
			if (val)  snprintf(val, vcap, __VA_ARGS__);           \
			if (xoff) *xoff = (o);                                \
			if (xlen) *xlen = (l);                                \
			return 1;                                             \
		}                                                             \
		(*seen)++;                                                    \
	} while (0)
/* The ordinary case: a row about one named field of the record. */
#define ROWF(nm, f, ...) ROWX(nm, AT(f), SZ(f), __VA_ARGS__)
/* A row about no particular bytes - a note derived from a flag. */
#define ROW(nm, ...)     ROWX(nm, 0, 0, __VA_ARGS__)

	ROWF("verb", verb, "%s", kof_evt_verb_name(e->verb));
	ROWF("pid", pid, "%lu", (unsigned long)e->pid);
	if (e->actor_pid && e->actor_pid != e->pid)
		ROWF("actor", actor_pid, "%lu", (unsigned long)e->actor_pid);
	if (e->ppid)
		ROWF("ppid", ppid, "%lu", (unsigned long)e->ppid);
	if (e->tid)
		ROWF("tid", tid, "%lu", (unsigned long)e->tid);
	ROWF("stamp", stamp, "%llu", (unsigned long long)e->stamp);
	ROWF("seq", seq, "%llu", (unsigned long long)e->seq);
	/*
	 * THE PER-VERB PAYLOAD, one block per kind.
	 *
	 * Reached through the accessors like every other reader, so a row can
	 * only appear on an event whose verb owns the field it names - which
	 * is stronger than the old "if it is non-zero" test: that showed a
	 * `session` row for anything whose bytes at that offset happened not
	 * to be zero, whatever the event actually was.
	 */
	{
		const struct kof_evt_proc *pr = kof_evt_as_proc(e);

		if (pr && pr->create_time)
			ROWF("created", u.proc.create_time, "%llu",
			     (unsigned long long)pr->create_time);
		if (pr && pr->session_id)
			ROWF("session", u.proc.session_id, "%lu",
			     (unsigned long)pr->session_id);
	}
	if (e->verb == KOF_EVT_PROC_STOP) {
		const struct kof_evt_proc *pr = kof_evt_as_proc(e);

		if (pr)
			ROWF("exit", u.proc.exit_code, "%lu",
			     (unsigned long)pr->exit_code);
	}

	if (*kof_evt_image(e))
		ROWX("image", (uint16_t)(AT(text) + e->off_image),
		     (uint16_t)strlen(kof_evt_image(e)),
		     "%s", kof_evt_image(e));
	/*
	 * THE OBJECT, WHICH IS A PATH FOR EVERY VERB BUT ONE.
	 *
	 * An AMSI submission is CONTENT: length-delimited bytes that may hold
	 * NULs and may hold terminal escapes. Formatted with %s like the paths
	 * beside it, a UTF-16 script block came out as a single character - the
	 * high byte of the first letter is a NUL and that is where the string
	 * ended. The one field the whole subscription exists for was showing
	 * one letter of itself.
	 *
	 * So a content object is written out byte by byte, printable ones as
	 * themselves and everything else as a dot - the same rendering
	 * kof_evt_render uses, for the same two reasons. The count is said
	 * first, because "392 B" is the fact a reader needs before deciding
	 * whether to go and read it in the dump.
	 */
	if (kof_evt_content(e, NULL, NULL) && e->content_len &&
	    obj_extent(e) != 0) {
		if (*seen == want) {
			const char *ct = NULL;
			size_t cn = 0;

			if (name)
				snprintf(name, ncap, "%s", "object");
			if (val && vcap) {
				/*
				 * NO "392 B" IN FRONT OF IT. The row already
				 * carries its length in the offset column -
				 * "0077+392" - and repeating it here made the
				 * value seven characters longer than the
				 * content, so the "+N more" that counts what
				 * did not fit counted the label too and gave a
				 * number that was not the number of bytes left.
				 */
				(void)kof_evt_content(e, &ct, &cn);
				(void)content_readable(ct, cn, val, vcap);
			}
			if (xoff) *xoff = (uint16_t)(AT(text) + e->off_object);
			if (xlen) *xlen = obj_extent(e);
			return 1;
		}
		(*seen)++;
	} else if (*kof_evt_object(e)) {
		ROWX("object", (uint16_t)(AT(text) + e->off_object),
		     obj_extent(e), "%s", kof_evt_object(e));
	}
	if (*kof_evt_cmdline(e))
		ROWX("cmdline", (uint16_t)(AT(text) + e->off_cmdline),
		     (uint16_t)strlen(kof_evt_cmdline(e)),
		     "%s", kof_evt_cmdline(e));

	if (e->loc)
		ROWF("where", loc, "%s", kof_loc_name(e->loc));
	/*
	 * The technique, HERE and not on the event line - see the note in
	 * kofevt.h. A properties panel is somebody asking about one event on
	 * purpose, which is a different thing from a stream scrolling past.
	 */
	if (e->attack)
		ROWF("technique", attack, "%s %s", kof_attack_id(e->attack),
		     kof_attack_name(e->attack));

	/*
	 * THE ADDRESS AND THE PORT ARE TWO ROWS, because they are two ranges.
	 *
	 * They read as one fact and they were written as one row - "10.0.0.5:443"
	 * over net_daddr - which needs an extent, and there is no single extent
	 * to give it: the struct groups its fields by width, so the address is
	 * at 0x44 and the port is twelve bytes later at 0x50. The row claimed
	 * four bytes plus two and got the address followed by the first half of
	 * net_saddr - it lit a field it was not about and never lit the port at
	 * all.
	 *
	 * A row maps to one range. Two facts in two places are two rows, and
	 * the combined form still exists where it costs nothing: kof_evt_render
	 * writes "10.0.0.5:443" on montrace's single line, which is a sentence
	 * rather than a table and has no bytes to point at.
	 */
	{
		const struct kof_evt_net *nt = kof_evt_as_net(e);

		if (nt && (!kof_evt_ip_is_unset(nt->daddr) || nt->dport)) {
			char ip[KOF_IP_STR_MAX];

			/*
			 * The row covers all sixteen bytes whether the address
			 * is v4 or v6, because that is the extent the field
			 * occupies - an IPv4-mapped address is the low four
			 * bytes of a sixteen-byte field, and lighting only
			 * those would tell a reader the record is shaped some
			 * other way than it is.
			 */
			ROWF("peer", u.net.daddr, "%s",
			     kof_evt_ip_str(nt->daddr, ip, sizeof ip));
		}
		if (nt && nt->dport) {
			/* Network order on the wire, host order to read. */
			uint16_t dp = (uint16_t)((nt->dport >> 8) |
						 (nt->dport << 8));

			ROWF("peer port", u.net.dport, "%u", (unsigned)dp);
		}
		if (nt && nt->size)
			ROWF("bytes", u.net.size, "%lu",
			     (unsigned long)nt->size);
	}
	{
		const struct kof_evt_file *fl = kof_evt_as_file(e);

		/* A write's length, which used to be reported in the field
		 * named after the network - see struct kof_evt_file. */
		if (fl && fl->size)
			ROWF("bytes", u.file.size, "%lu",
			     (unsigned long)fl->size);
		/* Zero is a legal offset - a write at the start of a file - so
		 * the row is offered whenever there is a length to go with it
		 * rather than whenever the offset is non-zero. */
		if (fl && fl->size)
			ROWF("at offset", u.file.offset, "%llu",
			     (unsigned long long)fl->offset);
		if (fl && fl->key)
			ROWF("file key", u.file.key, "0x%llx",
			     (unsigned long long)fl->key);
	}
	{
		const struct kof_evt_mem *mm = kof_evt_as_mem(e);

		if (mm && mm->addr)
			ROWF("addr", u.mem.addr, "0x%llx",
			     (unsigned long long)mm->addr);
		if (mm && mm->addr_size)
			ROWF("addr size", u.mem.addr_size, "%llu",
			     (unsigned long long)mm->addr_size);
	}
	/*
	 * THE ID AND THE SUBSYSTEM THAT NUMBERED IT, together.
	 *
	 * An id on its own is not a fact about anything: Windows numbers each
	 * provider's events from one, so "id 12" is a file event and a network
	 * connection at the same time. Shown as two rows because they are two
	 * fields at two offsets and the panel maps rows to bytes - the pairing
	 * is what the reader needs, and putting them next to each other is how
	 * a table says that.
	 */
	if (e->raw_id) {
		ROWF("raw id", raw_id, "%u", (unsigned)e->raw_id);
		if (e->source)
			ROWF("from", source, "%s",
			     kof_evt_source_name(e->source));
	}
	/*
	 * ONLY WHEN IT SAYS SOMETHING.
	 *
	 * This was unconditional, and it printed on every row of every record:
	 * "windows" repeated a thousand times in a log whose header already
	 * says windows, and - worse - "unknown" repeated a thousand times
	 * whenever the collector left the field alone, which the network path
	 * does. A row reading "source unknown" looks like a fact about the
	 * event; it is a fact about a field nobody filled in, and the two are
	 * not distinguishable once it is on screen.
	 *
	 * The platform belongs to the LOG, not the record - the header carries
	 * it and every reader has already seen it. What this row is for is the
	 * case the header cannot answer: a stream merged from more than one
	 * collector. So it appears exactly when the record was stamped, and
	 * says nothing when it was not.
	 */
	if (e->os)
		ROWF("source", os, "%s", (e->os & KOF_OS_WINDOWS) ? "windows" :
			    (e->os & KOF_OS_LINUX) ? "linux" : "unknown");

	/*
	 * The flags LAST and only when set, because each one qualifies
	 * everything above it: a truncated path, a field the collector could
	 * not supply, an entry point in no mapped image.
	 */
	/*
	 * THE FLAG ROWS, WHICH ARE NOT FIELDS AND MUST NOT READ AS ONE.
	 *
	 * They were all called "note", which is not the name of anything - so
	 * a panel that puts a name in a column had a column of rows labelled
	 * "note" and no way to tell whether one was a warning, an error, or a
	 * remark. That is the wrong question to leave a reader holding, because
	 * the answer changes what they do next.
	 *
	 * Two kinds, named for what they mean:
	 *
	 *   incomplete - THIS RECORD IS SHORT OF WHAT IT SHOULD HOLD. Nothing
	 *                in it is wrong; something is absent, and a rule that
	 *                matched on the absent part would be deciding on a
	 *                field the collector never wrote.
	 *
	 *   anomaly    - THE RECORD IS COMPLETE AND WHAT IT DESCRIBES IS ODD.
	 *                Not a defect in the collection: a finding about the
	 *                event, and the reason several of these events are
	 *                collected at all.
	 *
	 * Both carry a ZERO extent, which is how a caller tells them from a
	 * field without matching on the name - see kof_evt_field_extent.
	 */
	if (e->flags & KOF_EF_TRUNCATED)
		ROW("incomplete", "text was cut");
	if (e->flags & KOF_EF_PARTIAL)
		ROW("incomplete", "fields missing (0x%x)", (unsigned)e->miss);
	if (e->flags & KOF_EF_CMDLINE_RACED)
		ROW("incomplete", "command line lost to the process exiting");
	if (e->flags & KOF_EF_UNBACKED)
		ROW("anomaly", "entry point in no mapped image");
	if (e->flags & KOF_EF_LATE_LOAD)
		ROW("anomaly", "module mapped long after process start");
#undef ROW
#undef ROWF
#undef ROWX
#undef SZ
#undef AT
	return 0;
}

/*
 * THE ORDER THE ROWS COME OUT IN, which is the order the BYTES are in.
 *
 * field_at declares the rows in the order they make sense to write: what
 * happened, then to whom, then when. Read beside a hex dump that is the wrong
 * order, and wrong in the way that costs the most - a reader following the
 * colours down the dump finds them scattered up and down the list, so the two
 * halves have to be searched rather than read across. Sorted by offset they
 * run in step: row three is below row two in both panes.
 *
 * The rows that name NO bytes go last, together. They are notes derived from
 * flags rather than fields, they have nowhere to sit in a layout order, and
 * putting them at offset zero - which is what sorting them by their zero would
 * do - would file them under `stamp`.
 *
 * An insertion sort over at most a dozen rows, rebuilt per call. It is called
 * once per drawn row of a panel that is at most half a terminal, so the whole
 * cost is bounded by the screen; an index cached on the record would have to
 * be invalidated by every writer of it, and there are several.
 */
#define ORDER_MAX 32u

static unsigned row_order(const struct kof_evt *e, uint8_t *ord)
{
	unsigned n = 0, i;

	for (i = 0; i < ORDER_MAX; i++) {
		unsigned seen = 0;
		uint16_t o = 0, l = 0;
		unsigned k;

		if (!field_at(e, i, &seen, NULL, 0, NULL, 0, &o, &l))
			break;
		/* Insert by (has bytes, then offset), keeping equals in the
		 * order they were declared - two rows over one range is a bug
		 * in the table, and a stable order makes it look like one. */
		for (k = n; k > 0; k--) {
			unsigned seen2 = 0;
			uint16_t po = 0, pl = 0;

			(void)field_at(e, ord[k - 1u], &seen2, NULL, 0, NULL, 0,
				       &po, &pl);
			if (pl == 0 && l != 0)
				ord[k] = ord[k - 1u];
			else if (pl != 0 && l != 0 && po > o)
				ord[k] = ord[k - 1u];
			else
				break;
		}
		ord[k] = (uint8_t)i;
		n++;
	}
	return n;
}

int kof_evt_field(const struct kof_evt *e, unsigned i,
		  char *name, size_t ncap, char *val, size_t vcap)
{
	uint8_t ord[ORDER_MAX];
	unsigned seen = 0, n;

	if (!e || !name || !val || ncap == 0 || vcap == 0)
		return 0;
	name[0] = val[0] = '\0';
	n = row_order(e, ord);
	if (i >= n)
		return 0;
	return field_at(e, ord[i], &seen, name, ncap, val, vcap, NULL, NULL);
}

int kof_evt_field_extent(const struct kof_evt *e, unsigned i,
			 uint16_t *off, uint16_t *len)
{
	uint8_t ord[ORDER_MAX];
	unsigned seen = 0, n;
	uint16_t o = 0, l = 0;

	if (!e)
		return 0;
	n = row_order(e, ord);
	if (i >= n)
		return 0;
	if (!field_at(e, ord[i], &seen, NULL, 0, NULL, 0, &o, &l))
		return 0;
	/*
	 * A row about no particular bytes - a note derived from a flag - is
	 * still a row, and says so with a zero length rather than by failing.
	 * A caller highlighting on it would otherwise light up the first byte
	 * of the record for a note about the last.
	 */
	if (off) *off = o;
	if (len) *len = l;
	return 1;
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
	 *
	 * BUT NOT content_len ON ITS OWN EITHER. It is a length without a
	 * pointer, and the pointer is off_object, which the conversion between
	 * the collector's record and this one may have set to ABSENT - it does
	 * that whenever an offset fell outside the bytes that got copied. The
	 * pair was returned unchecked: kof_evt_object gave back the empty
	 * string at the end of the arena, content_len said four hundred, and
	 * every caller read four hundred bytes past it. A viewer printed the
	 * struct that followed; a scanner would have matched on it.
	 *
	 * So the length is clamped to the bytes that are actually THERE, and a
	 * content_len with no object behind it reports zero rather than a
	 * number with nothing under it.
	 */
	if (e->content_len && e->off_object != KOF_TEXT_NONE &&
	    e->off_object < sizeof e->text) {
		size_t room = sizeof e->text - e->off_object;
		size_t n = e->content_len;

		if (n > room)
			n = room;
		if (text) *text = t;
		if (len)  *len  = n;
		return n != 0;
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
