/*
 * wrender.c - see wrender.h.
 */

#include <stdio.h>
#include <string.h>

#include <windows.h>

#include "wrender.h"

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

void wm_render(const struct kofw_evt *e, double secs, const char *who,
	       struct wm_tally *t)
{
	printf("%8.3f  %-9s pid=%-6lu %-20s", secs,
	       kofw_evt_type_name(e->type), (unsigned long)e->pid,
	       who && *who ? who : "?");

	switch (e->type) {
	case KOFW_EVT_PROC_START:
		t->proc++;
		printf("  ppid=%lu  %s", (unsigned long)e->ppid,
		       kofw_evt_image(e));
		break;
	case KOFW_EVT_PROC_STOP:
		printf("  exit=%lu", (unsigned long)e->exit_code);
		break;
	case KOFW_EVT_IMAGE_LOAD:
		t->image++;
		printf("  [%s] %s", kofw_loc_name(e->obj_loc),
		       kofw_evt_object(e));
		break;
	case KOFW_EVT_FILE_NEW:
		t->file_new++;
		printf("  [%s] %s", kofw_loc_name(e->obj_loc),
		       kofw_evt_object(e));
		break;
	case KOFW_EVT_FILE_DELETE:
		t->file_del++;
		printf("  [%s] %s", kofw_loc_name(e->obj_loc),
		       kofw_evt_object(e));
		break;
	case KOFW_EVT_FILE_RENAME:
		t->file_ren++;
		printf("  [%s] %s", kofw_loc_name(e->obj_loc),
		       kofw_evt_object(e));
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

		if (e->type == KOFW_EVT_NET_CONNECT)
			t->conn++;
		else if (e->type == KOFW_EVT_NET_SEND)
			t->bytes_sent += e->net_size;
		else if (e->type == KOFW_EVT_NET_RECV)
			t->bytes_recv += e->net_size;

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
		t->raw++;
		printf("  [prov %u id %u v%u]  %s", (unsigned)e->provider,
		       (unsigned)e->raw_id, (unsigned)e->raw_version,
		       kofw_evt_object(e));
		break;
	}

	if (e->flags & KOFW_EF_TRUNCATED)
		printf("  [cut]");
	/* Printed, never hidden: a field the decode could not supply is the
	 * difference between a fact and a zero. */
	if (e->flags & KOFW_EF_PARTIAL)
		printf("  [miss 0x%x]", (unsigned)e->miss);
	putchar('\n');
}

void wm_print_tally(const struct wm_tally *t, double secs, const char *what,
		    uint64_t suppressed)
{
	fprintf(stderr,
		"\n-- %.1fs, %s\n"
		"   processes started : %llu\n"
		"   modules loaded    : %llu\n"
		"   files created     : %llu\n"
		"   files deleted     : %llu\n"
		"   files renamed     : %llu\n"
		"   connections       : %llu\n"
		"   bytes sent/recv   : %llu / %llu\n"
		"   untyped events    : %llu\n"
		"   filtered out      : %llu\n",
		secs, what,
		(unsigned long long)t->proc,
		(unsigned long long)t->image,
		(unsigned long long)t->file_new,
		(unsigned long long)t->file_del,
		(unsigned long long)t->file_ren,
		(unsigned long long)t->conn,
		(unsigned long long)t->bytes_sent,
		(unsigned long long)t->bytes_recv,
		(unsigned long long)t->raw,
		(unsigned long long)suppressed);
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
	if (h->schema_full)
		fprintf(stderr,
			"   INCOMPLETE: the schema cache is FULL - %llu event(s) "
			"were dropped whole and every new event id will be too; "
			"run with --schema to see what it filled up on\n",
			(unsigned long long)h->schema_full);
}
