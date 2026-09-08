/*
 * wrender.c - see wrender.h.
 */

#include <stdio.h>
#include <string.h>

#include <windows.h>

#include "wrender.h"

void wm_banner(const char *tool)
{
	fprintf(stderr, "%s (kofgrille) build %llu\n", tool,
		(unsigned long long)KOFENG_BUILD);
	if (KOFENG_BUILD == 0u)
		fputs("  built without a build stamp - cannot tell you which "
		      "build this is\n", stderr);
	fputs("  collects: process, image, file, file-write, network, "
	      "registry, thread\n"
	      "  typed:    process, image, file, network\n"
	      "  UNtyped (arrive as `raw`): registry, thread, IPv6 - their\n"
	      "            event ids are not established yet, so --raw must be\n"
	      "            on to see them at all. See wevt_decode.c.\n",
	      stderr);
}

const char *wm_leaf(const char *path)
{
	const char *last = path;

	for (; *path; path++) {
		if (*path == '\\' || *path == '/')
			last = path + 1;
	}
	return last;
}

double wm_secs_since(uint64_t t0, uint64_t t)
{
	int64_t d = (int64_t)(t - t0);

	return d < 0 ? 0.0 : (double)d / (double)KOFW_TICKS_PER_SEC;
}

uint64_t wm_now(void)
{
	FILETIME       ft;
	ULARGE_INTEGER u;

	GetSystemTimeAsFileTime(&ft);
	u.LowPart  = ft.dwLowDateTime;
	u.HighPart = ft.dwHighDateTime;
	return u.QuadPart;
}

/*
 * COUNTING, SEPARATED FROM PRINTING.
 *
 * One switch, so a --quiet run and a loud run cannot come back with different
 * totals for the same stream. The tally used to be incremented inside the
 * render switch, which meant the numbers were a side effect of somebody
 * looking at them.
 */
void wm_count(const struct kofw_evt *e, struct wm_tally *t)
{
	switch (e->type) {
	case KOFW_EVT_PROC_START:     t->proc++;     break;
	case KOFW_EVT_IMAGE_LOAD:     t->image++;    break;
	case KOFW_EVT_FILE_NEW:       t->file_new++; break;
	case KOFW_EVT_FILE_DELETE:    t->file_del++; break;
	case KOFW_EVT_FILE_RENAME:    t->file_ren++; break;
	case KOFW_EVT_FILE_WRITE:     t->file_wr++;  break;
	case KOFW_EVT_REG_CREATE:
	case KOFW_EVT_REG_SET_VALUE:
	case KOFW_EVT_REG_DELETE:     t->reg++;      break;
	case KOFW_EVT_NET_CONNECT:    t->conn++;     break;
	case KOFW_EVT_NET_SEND:       t->bytes_sent += e->net_size; break;
	case KOFW_EVT_NET_RECV:       t->bytes_recv += e->net_size; break;
	case KOFW_EVT_PROC_STOP:
	case KOFW_EVT_IMAGE_UNLOAD:
	case KOFW_EVT_NET_DISCONNECT:
	case KOFW_EVT_THREAD_START:
	case KOFW_EVT_THREAD_STOP:                   break;
	default:                      t->raw++;      break;
	}
}

void wm_render(const struct kofw_evt *e, double secs, const char *who,
	       struct wm_tally *t)
{
	wm_count(e, t);

	printf("%8.3f  %-9s pid=%-6lu %-20s", secs,
	       kofw_evt_type_name(e->type), (unsigned long)e->pid,
	       who && *who ? who : "?");

	switch (e->type) {
	case KOFW_EVT_PROC_START:
		printf("  ppid=%lu  %s", (unsigned long)e->ppid,
		       kofw_evt_image(e));
		break;
	case KOFW_EVT_PROC_STOP:
		printf("  exit=%lu", (unsigned long)e->exit_code);
		break;
	case KOFW_EVT_IMAGE_LOAD:
		printf("  [%s] %s", kofw_loc_name(e->obj_loc),
		       kofw_evt_object(e));
		break;
	case KOFW_EVT_IMAGE_UNLOAD:
		printf("  [%s] %s", kofw_loc_name(e->obj_loc),
		       kofw_evt_object(e));
		break;
	/* Unreachable until type_of() learns the ids - kept so that typing
	 * them is a one-line change there and not two. */
	case KOFW_EVT_THREAD_START:
	case KOFW_EVT_THREAD_STOP:
		printf("  start=0x%llx", (unsigned long long)e->addr);
		break;
	case KOFW_EVT_FILE_NEW:
		printf("  [%s] %s", kofw_loc_name(e->obj_loc),
		       kofw_evt_object(e));
		break;
	case KOFW_EVT_FILE_DELETE:
		printf("  [%s] %s", kofw_loc_name(e->obj_loc),
		       kofw_evt_object(e));
		break;
	case KOFW_EVT_FILE_RENAME:
		printf("  [%s] %s", kofw_loc_name(e->obj_loc),
		       kofw_evt_object(e));
		break;
	case KOFW_EVT_FILE_WRITE:
		printf("  [%s] %s", kofw_loc_name(e->obj_loc),
		       kofw_evt_object(e));
		if (e->net_size)
			printf("  %lu bytes", (unsigned long)e->net_size);
		break;

	/*
	 * The registry path goes in the same column every other object path
	 * goes in, so a reader scanning for "what did it touch" reads one
	 * column rather than learning where each provider hides its answer.
	 */
	case KOFW_EVT_REG_CREATE:
	case KOFW_EVT_REG_SET_VALUE:
	case KOFW_EVT_REG_DELETE:
		printf("  %s", kofw_evt_object(e));
		break;

	case KOFW_EVT_NET_CONNECT:
	case KOFW_EVT_NET_DISCONNECT:
	case KOFW_EVT_NET_SEND:
	case KOFW_EVT_NET_RECV: {
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

		printf("  %lu.%lu.%lu.%lu:%u",
		       (unsigned long)(d & 0xffu),
		       (unsigned long)((d >> 8) & 0xffu),
		       (unsigned long)((d >> 16) & 0xffu),
		       (unsigned long)((d >> 24) & 0xffu), (unsigned)dp);
		if (e->net_size)
			printf("  %lu bytes", (unsigned long)e->net_size);
		break;
	}

	default:
		printf("  [%s id %u v%u]", kofw_provider_name(e->provider),
		       (unsigned)e->raw_id, (unsigned)e->raw_version);
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
			printf("  addr=0x%llx", (unsigned long long)e->addr);
		if (*kofw_evt_object(e))
			printf("  %s", kofw_evt_object(e));
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
	if (e->attack != KOFW_ATT_NONE)
		printf("  <%s %s>", kofw_attack_id(e->attack),
		       kofw_attack_name(e->attack));

	if (e->flags & KOFW_EF_TRUNCATED)
		printf("  [cut]");
	/* Printed, never hidden: a field the decode could not supply is the
	 * difference between a fact and a zero. */
	if (e->flags & KOFW_EF_PARTIAL)
		printf("  [miss 0x%x]", (unsigned)e->miss);
	putchar('\n');
}

void wm_print_tally(const struct wm_tally *t, double secs, const char *what,
		    uint64_t suppressed, uint64_t h_loc, uint64_t h_scope,
		    uint64_t h_type)
{
	fprintf(stderr,
		"\n-- %.1fs, %s\n"
		"   processes started : %llu\n"
		"   modules loaded    : %llu\n"
		"   files created     : %llu\n"
		"   files deleted     : %llu\n"
		"   files renamed     : %llu\n"
		"   files written     : %llu\n"
		"   registry changes  : %llu\n"
		"   connections       : %llu\n"
		"   bytes sent/recv   : %llu / %llu\n"
		"   untyped events    : %llu\n"
		"   filtered out      : %llu"
		"  (location %llu, out of tree %llu, type %llu)\n",
		secs, what,
		(unsigned long long)t->proc,
		(unsigned long long)t->image,
		(unsigned long long)t->file_new,
		(unsigned long long)t->file_del,
		(unsigned long long)t->file_ren,
		(unsigned long long)t->file_wr,
		(unsigned long long)t->reg,
		(unsigned long long)t->conn,
		(unsigned long long)t->bytes_sent,
		(unsigned long long)t->bytes_recv,
		(unsigned long long)t->raw,
		(unsigned long long)suppressed,
		(unsigned long long)h_loc, (unsigned long long)h_scope,
		(unsigned long long)h_type);
}

void wm_print_health(const struct kofw_health *h, double secs)
{
	fprintf(stderr,
		"-- %6.1fs  kept %llu (%.1f/s)  ring drop %llu  high-water %llu"
		"  etw lost %lu/%lu/%lu  undecoded %llu  self %llu\n",
		secs,
		(unsigned long long)h->produced,
		secs > 0.0 ? (double)h->produced / secs : 0.0,
		(unsigned long long)h->ring_dropped,
		(unsigned long long)h->ring_high_water,
		(unsigned long)h->etw_events_lost,
		(unsigned long)h->etw_buffers_lost,
		(unsigned long)h->etw_rt_buf_lost,
		(unsigned long long)h->decode_failed,
		(unsigned long long)h->skipped_self);

	if (h->ring_dropped || h->etw_events_lost || h->etw_rt_buf_lost ||
	    h->seq_gaps)
		fprintf(stderr,
			"   INCOMPLETE: ring dropped %llu, seq gaps %llu, "
			"etw lost %lu/%lu\n",
			(unsigned long long)h->ring_dropped,
			(unsigned long long)h->seq_gaps,
			(unsigned long)h->etw_events_lost,
			(unsigned long)h->etw_rt_buf_lost);

	if (h->untracked)
		fprintf(stderr,
			"   INCOMPLETE: %llu process(es) could not be tracked; "
			"the scoped view is missing their events\n",
			(unsigned long long)h->untracked);

	/*
	 * Its own line, and worded as a state rather than a count, because that
	 * is what it is: the collector has stopped learning event shapes, so
	 * every id first seen from here on is discarded whole. Everything else
	 * above says how much was lost; this one says the losses will continue.
	 */
	/*
	 * A REFUSED PROVIDER IS THE FIRST THING TO PRINT AND THE LAST THING
	 * ANYBODY GUESSES.
	 *
	 * Everything else in this function says how much was lost. This one
	 * says a whole class of event was never collected at all - and it is
	 * the difference between "the sample did no network activity" and "the
	 * network provider never started". Those read identically in a trace
	 * and call for opposite next steps.
	 */
	{
		uint32_t missing = h->sub_asked & ~h->sub_enabled;
		uint32_t b;

		if (missing) {
			fputs("   INCOMPLETE: provider(s) REFUSED and never "
			      "collected:", stderr);
			for (b = 1u; b; b <<= 1) {
				if (missing & b)
					fprintf(stderr, " %s",
						kofw_sub_name(b));
			}
			fputs("\n", stderr);
		}
	}

	if (h->schema_full)
		fprintf(stderr,
			"   INCOMPLETE: the schema cache is FULL - %llu event(s) "
			"were dropped whole and every new event id will be too; "
			"run with --schema to see what it filled up on\n",
			(unsigned long long)h->schema_full);
}
