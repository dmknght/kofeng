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
	case KOF_EVT_AMSI_SCAN:
		/* The submitted content, which is a PREFIX - see
		 * KOF_EVT_AMSI_SCAN. The [cut] marker the common tail adds is
		 * doing real work here: unlike a path, a script block is
		 * usually longer than the arena, so most of these are
		 * legitimately incomplete rather than exceptionally so. */
		fprintf(out, "  %s", kof_evt_object(e));
		break;
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
	 * THE TECHNIQUE, WHERE THE PATH ITSELF IS ONE.
	 *
	 * Printed after the path rather than instead of it, always. A
	 * classification is a decision that can be wrong and the raw path is
	 * the only thing that lets somebody check it - which is the same rule
	 * the record follows for obj_loc.
	 */
	if (e->attack != KOF_ATT_NONE)
		fprintf(out, "  <%s %s>", kof_attack_id(e->attack),
		       kof_attack_name(e->attack));

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

