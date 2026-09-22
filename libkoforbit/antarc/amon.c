/*
 * amon.c - see amon.h.
 *
 * Every decision in here was made in kofwatcher/kofwatchtower.c first and is
 * moved rather than rewritten: the comments that carry the measurements come
 * with it, because the measurement is the reason and a reason that stays
 * behind in the file it was written in is a reason the next reader never sees.
 */

#define _GNU_SOURCE

#include <poll.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "amon.h"

struct kofa_mon {
	struct kofa_fan *fan;
	struct kofa_pev *pev;

	const struct kof_mon_api *fan_api;
	const struct kof_mon_api *pev_api;

	int pev_err;
	int turn;            /* which stream is asked first - see next() */

	struct kof_mon_api api;
};

/*
 * ONE EXEC IS NOT TWO EVENTS - see amon.h.
 *
 * Returns 1 to keep the record, and 0 the way `next` reports "nothing this
 * time", which the caller's loop already handles because a wait expiring is
 * the same answer.
 */
static int keep(struct kofa_mon *m, struct kof_evt *out)
{
	const char *img;

	if (!m->pev || out->verb != KOF_EVT_IMAGE_LOAD)
		return 1;
	if (out->miss & KOF_F_PID)
		return 1;              /* degraded fanotify: no pid to match */
	img = kof_evt_object(out);
	if (!img || !*img)
		return 1;
	/*
	 * AND BEFORE DECIDING, HAND THE PATH OVER.
	 *
	 * This record is fanotify's, and fanotify got the path from the kernel
	 * without racing anything. The process collector is about to need
	 * exactly that path for the start it will report a moment from now,
	 * and its own source for it is /proc, which a short-lived process
	 * empties before it can be read.
	 *
	 * Done here rather than after the duplicate test because a record that
	 * is ABOUT to be dropped as a duplicate is still the one carrying the
	 * path.
	 */
	kofa_pev_hint_image(m->pev, out->pid, img);
	/*
	 * No clock is offered: the two collectors stamp from different
	 * sources - fanotify records carry no time of their own here - so a
	 * window computed across them would compare two unrelated scales. The
	 * image match against a process still marked running is what decides,
	 * and apev drops the entry the moment the process exits.
	 */
	return !kofa_pev_is_own_image(m->pev, out->pid, img, 0);
}

/*
 * BOTH STREAMS ARE DRAINED FIRST, AND THEN BOTH ARE WAITED ON.
 *
 * Blocking on one of them was the bug. An earlier version alternated which one
 * got the wait, so half the time it sat on the file stream for the whole slice
 * while process records aged in a socket nobody was reading - and the things
 * worth catching do not last that long.
 *
 * So nothing blocks inside a collector. Both are asked with no wait, and if
 * neither had anything the session waits on both descriptors at once and asks
 * again. A collector that cannot be waited on says so with -1 and is given the
 * wait directly.
 */
static int mon_next(void *self, struct kof_evt *out, uint32_t wait_ms)
{
	struct kofa_mon *m = self;
	const struct kof_mon_api *a, *b;
	struct pollfd pf[2];
	int nf = 0, fa, fb;

	if (!m->pev_api)
		return kof_mon_next(m->fan_api, out, wait_ms);
	if (!m->fan_api)
		return kof_mon_next(m->pev_api, out, wait_ms);

	m->turn = !m->turn;
	a = m->turn ? m->pev_api : m->fan_api;
	b = m->turn ? m->fan_api : m->pev_api;

	if (kof_mon_next(a, out, 0))
		return keep(m, out);
	if (kof_mon_next(b, out, 0))
		return keep(m, out);

	fa = a->pollfd ? a->pollfd(a->self) : -1;
	fb = b->pollfd ? b->pollfd(b->self) : -1;
	if (fa < 0 || fb < 0) {
		if (kof_mon_next(fa < 0 ? a : b, out, wait_ms))
			return keep(m, out);
		if (kof_mon_next(fa < 0 ? b : a, out, 0))
			return keep(m, out);
		return 0;
	}
	pf[nf].fd = fa; pf[nf].events = POLLIN; pf[nf++].revents = 0;
	pf[nf].fd = fb; pf[nf].events = POLLIN; pf[nf++].revents = 0;
	if (poll(pf, (nfds_t)nf, (int)wait_ms) <= 0)
		return 0;
	if ((pf[0].revents & POLLIN) && kof_mon_next(a, out, 0))
		return keep(m, out);
	if ((pf[1].revents & POLLIN) && kof_mon_next(b, out, 0))
		return keep(m, out);
	return 0;
}

/*
 * THE PROCESS COLLECTOR IS THE ONE THAT KNOWS A PID'S NAME, and a file session
 * has no idea what a pid is called. Asking the file half would return the
 * empty string, which a renderer prints as unknown - so this asks the half
 * that has a table, and answers "" only when there is no such half.
 */
static const char *mon_name_of(void *self, uint32_t pid, uint64_t start_time)
{
	struct kofa_mon *m = self;

	if (m->pev_api && m->pev_api->name_of)
		return m->pev_api->name_of(m->pev_api->self, pid, start_time);
	return "";
}

/*
 * THE LOSSES OF BOTH, ADDED. A session that reported only one half's drops
 * would say a number that is true of a part and read as true of the whole.
 */
static void mon_health(void *self, struct kof_evt_health *out)
{
	struct kofa_mon *m = self;
	struct kof_evt_health h;

	memset(out, 0, sizeof *out);
	if (m->fan_api && m->fan_api->health) {
		memset(&h, 0, sizeof h);
		m->fan_api->health(m->fan_api->self, &h);
		*out = h;
	}
	if (m->pev_api && m->pev_api->health) {
		memset(&h, 0, sizeof h);
		m->pev_api->health(m->pev_api->self, &h);
		out->produced  += h.produced;
		out->dropped   += h.dropped;
		out->undecoded += h.undecoded;
		out->filtered  += h.filtered;
		out->seq_gaps  += h.seq_gaps;
		if (h.high_water > out->high_water)
			out->high_water = h.high_water;
	}
}

/* Both, in the order they were opened, so a reader sees which half said what. */
static void mon_print_extra(void *self, FILE *out)
{
	struct kofa_mon *m = self;

	if (m->fan_api && m->fan_api->print_extra)
		m->fan_api->print_extra(m->fan_api->self, out);
	if (m->pev_api && m->pev_api->print_extra)
		m->pev_api->print_extra(m->pev_api->self, out);
}

/*
 * NO DESCRIPTOR IS OFFERED when both halves are open: there are two, and the
 * whole point of mon_next is that it waits on both at once. Offering one would
 * let a caller wait on the file stream and never notice the process one.
 */
static int mon_pollfd(void *self)
{
	struct kofa_mon *m = self;

	if (m->fan_api && !m->pev_api && m->fan_api->pollfd)
		return m->fan_api->pollfd(m->fan_api->self);
	if (m->pev_api && !m->fan_api && m->pev_api->pollfd)
		return m->pev_api->pollfd(m->pev_api->self);
	return -1;
}

/*
 * The neutral close, so a caller holding only the api can end the session -
 * which is how kofmontrace ends it. Without this the api looked complete and
 * both collectors stayed open for the life of the process.
 */
static void mon_close(void *self)
{
	kofa_mon_free(self);
}

struct kofa_mon *kofa_mon_open(const struct kofa_mon_option *opt, int *err)
{
	struct kofa_mon *m = calloc(1, sizeof *m);
	struct kofa_mon_option o;
	int e = 0;

	if (err)
		*err = 0;
	if (!m)
		return NULL;
	memset(&o, 0, sizeof o);
	if (opt)
		o = *opt;

	m->fan = kofa_fan_open(&o.fan, &e);
	if (m->fan)
		m->fan_api = kofa_fan_api(m->fan);

	if (!o.no_procs) {
		struct kofa_pev_option po;

		memset(&po, 0, sizeof po);
		m->pev = kofa_pev_open(&po, &m->pev_err);
		if (m->pev)
			m->pev_api = kofa_pev_api(m->pev);
	}

	/*
	 * ONE HALF IS A SESSION. The connector needs a privilege the file
	 * collector does not, and a run with files alone still answers
	 * questions - so this fails only when NEITHER opened, and the reason
	 * reported is the file collector's because that is the half every
	 * caller expects.
	 */
	if (!m->fan_api && !m->pev_api) {
		if (err)
			*err = e;
		free(m);
		return NULL;
	}

	m->api.self        = m;
	m->api.close       = mon_close;
	m->api.next        = mon_next;
	m->api.health      = mon_health;
	m->api.name_of     = mon_name_of;
	m->api.print_extra = mon_print_extra;
	m->api.pollfd      = mon_pollfd;
	return m;
}

const struct kof_mon_api *kofa_mon_api(struct kofa_mon *m)
{
	return m ? &m->api : NULL;
}

struct kofa_fan *kofa_mon_fan(struct kofa_mon *m)   { return m ? m->fan : NULL; }
struct kofa_pev *kofa_mon_pev(struct kofa_mon *m)   { return m ? m->pev : NULL; }
int              kofa_mon_pev_err(struct kofa_mon *m) { return m ? m->pev_err : 0; }

void kofa_mon_free(struct kofa_mon *m)
{
	if (!m)
		return;
	if (m->pev)
		kofa_pev_close(m->pev);
	if (m->fan)
		kofa_fan_close(m->fan);
	free(m);
}
