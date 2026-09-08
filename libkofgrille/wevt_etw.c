/*
 * wevt_etw.c - the ETW session, the consumer thread, and the callback.
 *
 * THE CALLBACK IS THE ONLY PART OF THIS LIBRARY THE WHOLE MACHINE PAYS FOR.
 *
 * It runs on the ProcessTrace thread, and while it is inside the callback the
 * session's buffers are not being drained. Everything slow it does is paid for
 * twice: once as its own cost, and again as records ETW discards at its end
 * because the buffers filled while it was busy. So it does three things and
 * nothing else - refuse our own events, decode into a claimed ring slot,
 * commit - and every one of the expensive things a collector wants to do
 * (opening the image, hashing it, walking a process tree, writing a log)
 * happens on the consumer's thread instead.
 *
 * That is also why there is no logging here. A log write is file I/O, file I/O
 * raises file events, and the day a file provider is added this file would be
 * feeding itself.
 */

#include <stdlib.h>
#include <string.h>
#include <stdatomic.h>

#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>
#include <tdh.h>

#include "wcompat.h"

#include "kofgrille.h"
#include "wevt_ring.h"
#include "wevt_decode.h"
#include "wfilter.h"

/*
 * WINEVENT_KEYWORD_PROCESS and _IMAGE. Thread (0x20) is deliberately left off:
 * it is an order of magnitude more traffic than either of these and nothing
 * reads it.
 */
#define KW_PROCESS 0x10u
#define KW_IMAGE   0x40u

/*
 * WINEVENT_KEYWORD_THREAD. Off by default and worth its cost only for one
 * question - see KOFW_EVT_THREAD_START on why that question is the in-memory
 * load, and why nothing else in this file can answer it.
 */
#define KW_THREAD  0x20u

/*
 * KERNEL-FILE, AND THE LINE THIS DRAWS.
 *
 * CREATE_NEW_FILE (0x1000) fires when a file comes into existence.
 * DELETE_PATH (0x400) and RENAME_SETLINK_PATH (0x800) when one goes away or
 * moves. Those three are the whole subscription.
 *
 * What is NOT here is the point. CREATE (0x80) fires on every file a machine
 * OPENS, READ (0x100) and WRITE (0x200) on every operation against one, and
 * FILEIO/OP_END on the completions. Those are the keywords that make file
 * tracing famous for being unaffordable, and none of them carries evidence
 * anybody writes a rule against: "something read a file" is not a fact, "an
 * executable appeared in a startup directory" is.
 */
#define KW_FILE_MUTATE 0x1c00u

/*
 * WRITE (0x200) plus FILENAME (0x10), and the second is not optional company
 * for the first. A write event names its target by FileObject - a kernel
 * pointer - and never by path; FILENAME is the keyword that emits the
 * pointer-to-name mapping, so without it every write is a size against an
 * address nobody can resolve.
 */
#define KW_FILE_WRITE  0x0210u

/* IPv4 and IPv6, which is the entire keyword vocabulary this provider has. */
#define KW_NET_ALL     0x0030u

/*
 * KERNEL-REGISTRY: CREATE, SETVALUE and DELETE, and not the reads.
 *
 * This is the most expensive provider in the file. A desktop doing nothing
 * touches the registry thousands of times a second, and the overwhelming
 * majority of that is QUERY - which carries nothing anybody writes a rule
 * against, exactly as with a file being read. Subscribing to it would spend
 * the whole buffer budget on traffic that is discarded downstream, and the
 * records lost to make room would be the ones that mattered.
 *
 * The keyword bits are the provider's own and are NOT VERIFIED on a real
 * machine yet - the same standing as the GUID next to them in wevt_decode.c.
 * `logman query providers Microsoft-Windows-Kernel-Registry` prints the table
 * this assumes. A wrong keyword here is silent in the same way a wrong GUID
 * is: the session starts and the machine looks quiet.
 */
#define KW_REG_CREATE   0x0020u
#define KW_REG_SETVALUE 0x0100u
#define KW_REG_DELETE   0x0040u
#define KW_REG_MUTATE   (KW_REG_CREATE | KW_REG_SETVALUE | KW_REG_DELETE)

/*
 * NO EVENT-ID FILTER ON ANY PROVIDER ANY MORE, AND THAT IS THE POINT.
 *
 * Kernel-Process used to be enabled with EVENT_FILTER_TYPE_EVENT_ID naming
 * { 1, 2, 5, 6 } on the grounds that "Kernel-Process's ids are known". They
 * were assumed, not established - and a FilterIn list is the one construct
 * here that can exclude an event with no trace whatsoever. If ImageLoad is not
 * id 5 on some build, the session starts, the keyword is accepted, and no
 * module load is ever delivered. That failure is indistinguishable from a
 * machine that loads no modules, which is not a machine.
 *
 * The keywords already do the volume work - they are what stops the reads and
 * the thread churn - so the id filter was buying almost nothing and could cost
 * everything. Every provider here is now keyword-only, which is also the shape
 * a discovery run needs: an id nobody has typed yet arrives as RAW and shows up
 * in `--schema` with a count beside it, instead of being silently refused
 * upstream by a list somebody wrote from memory.
 */

#define NAME_MAX_CH 128u

struct kofw_mon {
	struct kofw_ring         ring;
	struct kofw_schema_cache schema;

	TRACEHANDLE session;
	TRACEHANDLE consumer;
	HANDLE      thread;
	HANDLE      wake;

	/* Set by kofw_mon_close, read by the buffer callback. The buffer
	 * callback returning FALSE is what makes ProcessTrace return. */
	volatile LONG stopping;

	DWORD   self_pid;
	int     trace_self;
	wchar_t name[NAME_MAX_CH];

	/* Consumer-side state: the filter and the process table it needs. Only
	 * kofw_mon_next touches these, and there is one consumer by
	 * construction, so they need no lock. */
	/* What was asked for and what the providers actually accepted. Set once
	 * at open, read by kofw_mon_health. */
	uint32_t sub_asked, sub_enabled;

	struct kofw_filter filter;
	struct kofw_ptab   ptab;
	uint64_t           filtered;
	uint64_t           seq_expect, seq_gaps;
	int                seq_started;

	_Atomic uint64_t skipped_self;
	_Atomic uint64_t decode_failed;

	/*
	 * EVENTS THAT ARRIVED, which is not events that were kept - and the
	 * difference is the whole point of it.
	 *
	 * kofw_evt.seq is stamped from this, not from ring.produced. Taking it
	 * from produced was the obvious thing and it was wrong: produced only
	 * advances on a successful commit, so a record the ring refused left no
	 * hole, every seq a consumer saw was contiguous, and kofw_health.seq_gaps
	 * could not be non-zero however much was lost. The counter a gap is
	 * measured against has to advance on ARRIVAL or it is not measuring
	 * arrivals.
	 */
	_Atomic uint64_t arrived;

	/* A second properties buffer, so a health query cannot clobber the one
	 * the session was started with. */
	EVENT_TRACE_PROPERTIES *qprops;
	ULONG                   qprops_sz;
};

/* ------------------------------------------------------------------ helpers */

const char *kofw_err_name(int err)
{
	switch (err) {
	case 0:                 return "ok";
	case KOFW_ERR_ARG:      return "bad argument";
	case KOFW_ERR_MEM:      return "out of memory";
	case KOFW_ERR_ACCESS:   return "not elevated";
	case KOFW_ERR_SESSION:  return "the trace session would not start";
	case KOFW_ERR_PROVIDER: return "the provider would not enable";
	case KOFW_ERR_CONSUMER: return "the trace session would not open";
	case KOFW_ERR_THREAD:   return "the consumer thread would not start";
	case KOFW_ERR_PLATFORM: return "built without the Windows collector";
	default:                return "unknown";
	}
}

static ULONG props_bytes(void)
{
	/* Room for the logger name and for an empty log file name after it.
	 * ETW copies both out of this one allocation. */
	return (ULONG)(sizeof(EVENT_TRACE_PROPERTIES) +
		       (NAME_MAX_CH + 2u) * 2u * sizeof(wchar_t));
}

static EVENT_TRACE_PROPERTIES *props_new(const wchar_t *name, ULONG buf_kb,
					 ULONG min_buf, ULONG max_buf,
					 int no_system_logger)
{
	ULONG sz = props_bytes();
	EVENT_TRACE_PROPERTIES *p = calloc(1, sz);

	if (!p)
		return NULL;

	p->Wnode.BufferSize = sz;
	p->Wnode.Flags      = WNODE_FLAG_TRACED_GUID;

	/*
	 * ClientContext 1 is QPC, and it chooses the clock SOURCE rather than
	 * the units a consumer sees. Not 2 (system time), whose resolution is a
	 * scheduler tick - coarser than the whole lifetime of the short-lived
	 * processes this exists to see, and useless for putting the per-CPU
	 * buffers back in order.
	 *
	 * What arrives in EventHeader.TimeStamp is that instant already
	 * converted to 100ns FILETIME units, because this consumer does not ask
	 * for PROCESS_TRACE_MODE_RAW_TIMESTAMP. That is the wanted answer - a
	 * wall clock at hardware resolution - and it is written down because the
	 * other reading cost a debugging session: raw counter ticks are what the
	 * name suggests and not what is delivered.
	 */
	p->Wnode.ClientContext = 1;

	/*
	 * REAL-TIME, AND MARKED AS A SYSTEM LOGGER.
	 *
	 * The second flag is not decoration. Several of the kernel providers -
	 * Kernel-Network among them - are "system" providers: EnableTraceEx2
	 * accepts them into an ordinary private session and reports success, the
	 * session runs, and not one event is ever delivered. There is no error
	 * anywhere in that sequence, which is the same silent-quiet-machine
	 * failure a wrong provider GUID produces and is why this comment exists
	 * rather than just the flag.
	 */
	p->LogFileMode        = EVENT_TRACE_REAL_TIME_MODE;
	if (!no_system_logger)
		p->LogFileMode |= EVENT_TRACE_SYSTEM_LOGGER_MODE;
	p->BufferSize         = buf_kb;
	p->MinimumBuffers     = min_buf;
	p->MaximumBuffers     = max_buf;

	/* Seconds, and this is the session's contribution to end-to-end latency:
	 * a buffer that is not full is not delivered until it is flushed. One is
	 * the smallest ETW accepts. */
	p->FlushTimer         = 1;

	p->LoggerNameOffset   = (ULONG)sizeof(EVENT_TRACE_PROPERTIES);
	/* Zero, and it must be: a real-time session writes no file, and a
	 * non-zero offset here asks for one. */
	p->LogFileNameOffset  = 0;

	if (name) {
		wchar_t *dst = (wchar_t *)((char *)p + p->LoggerNameOffset);
		size_t   i;
		for (i = 0; i + 1 < NAME_MAX_CH && name[i]; i++)
			dst[i] = name[i];
		dst[i] = 0;
	}
	return p;
}

/* ----------------------------------------------------------- the callbacks */

static ULONG WINAPI on_buffer(PEVENT_TRACE_LOGFILEW log)
{
	struct kofw_mon *m = (struct kofw_mon *)log->Context;

	/* FALSE stops ProcessTrace. This is the shutdown path: kofw_mon_close
	 * sets the flag and stops the session, and ProcessTrace returns at the
	 * next buffer boundary. */
	return m && m->stopping ? FALSE : TRUE;
}

static void WINAPI on_event(PEVENT_RECORD rec)
{
	struct kofw_mon *m = (struct kofw_mon *)rec->UserContext;
	struct kofw_evt *slot;
	uint64_t seq;

	if (!m)
		return;

	/*
	 * OUR OWN EVENTS, REFUSED BEFORE ANYTHING ELSE HAPPENS.
	 *
	 * This is the first line for a reason that is not tidiness. Anything
	 * this process does that raises an event - and once a file provider is
	 * added, reading a file to scan it raises several - arrives here, is
	 * handled, and causes more of the same. On a loaded machine that loop
	 * does not converge.
	 *
	 * It cannot be done in the provider instead: EVENT_FILTER_TYPE_PID is
	 * filter-IN, naming the only pids to trace, so there is no way to spell
	 * "everything except this one" there. The check has to be here, and
	 * being here it has to be before the decode that would otherwise cost
	 * more than the event is worth.
	 */
	if (!m->trace_self && rec->EventHeader.ProcessId == m->self_pid) {
		atomic_fetch_add_explicit(&m->skipped_self, 1u,
					  memory_order_relaxed);
		return;
	}

	/*
	 * TAKEN HERE, BEFORE ANYTHING CAN REFUSE THE RECORD.
	 *
	 * This number becomes kofw_evt.seq, and a gap in it is how a consumer
	 * learns something was lost - so it has to be claimed by the arrival
	 * rather than by the survival. Everything below this line can drop the
	 * event (the ring is full, the decode failed), and each of those now
	 * leaves exactly the hole it should.
	 *
	 * Self-skipped events are counted before it on purpose: those are not a
	 * loss, they are a deliberate exclusion, and putting them in the
	 * sequence would report the filter working as damage.
	 */
	seq = atomic_fetch_add_explicit(&m->arrived, 1u, memory_order_relaxed);

	slot = kofw_ring_claim(&m->ring);
	if (!slot)
		return;   /* the drop is already counted, and seq now has a hole */

	if (!kofw_decode(&m->schema, rec, slot)) {
		atomic_fetch_add_explicit(&m->decode_failed, 1u,
					  memory_order_relaxed);
		return;   /* claimed and not committed: the slot is reused */
	}

	slot->seq = seq;

	/*
	 * Woken only on the empty-to-nonempty edge, so a burst costs one wakeup
	 * rather than one per record. A consumer that misses the edge - the
	 * producer read a stale tail - is not stuck: kofw_mon_next caps each
	 * wait, so the worst case is latency, not a stall.
	 */
	if (kofw_ring_commit(&m->ring) == 0 && m->wake)
		SetEvent(m->wake);
}

/* --------------------------------------------------------------- the thread */

static DWORD WINAPI consume(LPVOID arg)
{
	struct kofw_mon *m = arg;

	/* Blocks until the session stops or on_buffer returns FALSE. This is why
	 * it needs a thread of its own. */
	(void)ProcessTrace(&m->consumer, 1, NULL, NULL);
	return 0;
}

/* ----------------------------------------------------------------- opening */

static int start_session(struct kofw_mon *m, const struct kofw_mon_option *o)
{
	const int nsl = o->no_system_logger;
	EVENT_TRACE_PROPERTIES *p;
	ULONG st;
	/*
	 * SIZED FOR EVERY PROVIDER ON, because that is what the tools now ask
	 * for by default.
	 *
	 * These were 64/8/64, chosen when the only subscription was process
	 * start and stop - single digits per second. With the registry and the
	 * file writes in the same session the rate is three orders of magnitude
	 * higher, and a session whose buffers fill discards records at ITS end,
	 * where this library cannot count them per subject. Buffers are cheap
	 * and the loss they prevent is not recoverable.
	 */
	ULONG kb   = o->buffer_kb    ? o->buffer_kb    : 128u;
	ULONG minb = o->min_buffers  ? o->min_buffers  : 32u;
	ULONG maxb = o->max_buffers  ? o->max_buffers  : 256u;

	p = props_new(m->name, kb, minb, maxb, nsl);
	if (!p)
		return KOFW_ERR_MEM;

	st = StartTraceW(&m->session, m->name, p);

	/*
	 * A LEFTOVER SESSION FROM A RUN THAT DIED.
	 *
	 * An ETW session is a kernel object that outlives whoever created it, so
	 * a crash leaves it running and buffering, and every later run fails
	 * here. Stopping it and retrying once is the only way this is usable
	 * during development - the alternative is a manual `logman stop` after
	 * every crash, which is a step somebody eventually skips and then
	 * reports the tool as broken.
	 */
	if (st == ERROR_ALREADY_EXISTS) {
		EVENT_TRACE_PROPERTIES *q = props_new(m->name, kb, minb, maxb, nsl);
		if (q) {
			(void)ControlTraceW(0, m->name, q,
					    EVENT_TRACE_CONTROL_STOP);
			free(q);
		}
		free(p);
		p = props_new(m->name, kb, minb, maxb, nsl);
		if (!p)
			return KOFW_ERR_MEM;
		st = StartTraceW(&m->session, m->name, p);
	}

	free(p);

	if (st == ERROR_ACCESS_DENIED)
		return KOFW_ERR_ACCESS;
	if (st != ERROR_SUCCESS)
		return KOFW_ERR_SESSION;
	return 0;
}

/*
 * Enable one provider. `ids`/`n_ids` NULL/0 means keyword-only, for a provider
 * whose event ids this build has not verified.
 */
static int enable_one(struct kofw_mon *m, const GUID *guid, ULONGLONG keyword,
		      const USHORT *ids, size_t n_ids)
{
	unsigned char buf[sizeof(EVENT_FILTER_EVENT_ID) + 16 * sizeof(USHORT)];
	EVENT_FILTER_EVENT_ID  *f = (EVENT_FILTER_EVENT_ID *)(void *)buf;
	EVENT_FILTER_DESCRIPTOR fd;
	ENABLE_TRACE_PARAMETERS tp;
	ULONG  st;
	size_t i;

	memset(&tp, 0, sizeof tp);
	tp.Version = ENABLE_TRACE_PARAMETERS_VERSION_2;

	if (ids && n_ids && n_ids <= 16) {
		memset(buf, 0, sizeof buf);
		f->FilterIn = TRUE;
		f->Count    = (USHORT)n_ids;
		for (i = 0; i < n_ids; i++)
			f->Events[i] = ids[i];

		memset(&fd, 0, sizeof fd);
		fd.Ptr  = (ULONGLONG)(uintptr_t)buf;
		fd.Size = (ULONG)(sizeof(EVENT_FILTER_EVENT_ID) +
				  (n_ids - 1u) * sizeof(USHORT));
		fd.Type = EVENT_FILTER_TYPE_EVENT_ID;

		tp.EnableFilterDesc = &fd;
		tp.FilterDescCount  = 1;
	}

	st = EnableTraceEx2(m->session, guid,
			    EVENT_CONTROL_CODE_ENABLE_PROVIDER,
			    TRACE_LEVEL_INFORMATION, keyword, 0, 0, &tp);

	return st == ERROR_SUCCESS ? 0 : KOFW_ERR_PROVIDER;
}

/*
 * ENABLE WHAT CAN BE ENABLED, AND RECORD WHAT COULD NOT.
 *
 * This used to return on the first refusal, which aborted kofw_mon_open and
 * threw away every provider that WOULD have worked. That is the wrong trade
 * twice over: the common case for a refusal is one provider that this build of
 * Windows spells differently, and losing the other four to it turns a partial
 * answer into no answer. It also made the failure unattributable - the caller
 * got "the provider would not enable" and no way to learn which one.
 *
 * Now every subscription is attempted, the successes are recorded in
 * m->sub_enabled, and the whole thing fails only if NOTHING enabled - because a
 * session with no provider is not a degraded collector, it is a thread waiting
 * for events that cannot come.
 */
static int enable_providers(struct kofw_mon *m, uint32_t subs)
{
	ULONGLONG kw = 0;

	m->sub_asked   = subs;
	m->sub_enabled = 0;

	if (subs & KOFW_SUB_PROCESS)
		kw |= KW_PROCESS;
	if (subs & KOFW_SUB_IMAGE)
		kw |= KW_IMAGE;
	if (subs & KOFW_SUB_THREAD)
		kw |= KW_THREAD;

	/*
	 * The process provider carries three subscriptions under three
	 * keywords, so it enables once and all three stand or fall together -
	 * there is no way to be told that one keyword of the three was refused.
	 */
	if (kw && enable_one(m, &KOFW_GUID_KERNEL_PROCESS, kw, NULL, 0) == 0)
		m->sub_enabled |= subs & (KOFW_SUB_PROCESS | KOFW_SUB_IMAGE |
					  KOFW_SUB_THREAD);

	if (subs & (KOFW_SUB_FILE | KOFW_SUB_FILE_WRITE)) {
		ULONGLONG fkw = 0;

		if (subs & KOFW_SUB_FILE)
			fkw |= KW_FILE_MUTATE;
		if (subs & KOFW_SUB_FILE_WRITE)
			fkw |= KW_FILE_WRITE;
		if (enable_one(m, &KOFW_GUID_KERNEL_FILE, fkw, NULL, 0) == 0)
			m->sub_enabled |= subs & (KOFW_SUB_FILE |
						  KOFW_SUB_FILE_WRITE);
	}

	if (subs & KOFW_SUB_NET) {
		if (enable_one(m, &KOFW_GUID_KERNEL_NET, KW_NET_ALL,
			       NULL, 0) == 0)
			m->sub_enabled |= KOFW_SUB_NET;
	}

	if (subs & KOFW_SUB_REGISTRY) {
		if (enable_one(m, &KOFW_GUID_KERNEL_REGISTRY, KW_REG_MUTATE,
			       NULL, 0) == 0)
			m->sub_enabled |= KOFW_SUB_REGISTRY;
	}

	return m->sub_enabled ? 0 : KOFW_ERR_PROVIDER;
}

static int open_consumer(struct kofw_mon *m)
{
	EVENT_TRACE_LOGFILEW lf;

	memset(&lf, 0, sizeof lf);
	lf.LoggerName          = m->name;
	lf.ProcessTraceMode    = PROCESS_TRACE_MODE_REAL_TIME |
				 PROCESS_TRACE_MODE_EVENT_RECORD;
	lf.EventRecordCallback = on_event;
	lf.BufferCallback      = on_buffer;
	lf.Context             = m;

	m->consumer = OpenTraceW(&lf);
	if (m->consumer == INVALID_PROCESSTRACE_HANDLE)
		return KOFW_ERR_CONSUMER;
	return 0;
}

struct kofw_mon *kofw_mon_open(const struct kofw_mon_option *opt, int *err)
{
	static const wchar_t DEFAULT_NAME[] = L"KofengEventMonitor";
	struct kofw_mon_option o;
	struct kofw_mon *m;
	int rc;

	if (err)
		*err = 0;

	memset(&o, 0, sizeof o);
	if (opt)
		o = *opt;

	m = calloc(1, sizeof *m);
	if (!m) {
		if (err) *err = KOFW_ERR_MEM;
		return NULL;
	}

	m->self_pid    = GetCurrentProcessId();
	kofw_ptab_init(&m->ptab);
	m->trace_self  = o.trace_self;
	atomic_init(&m->skipped_self, 0u);
	atomic_init(&m->decode_failed, 0u);
	atomic_init(&m->arrived, 0u);

	{
		const char *n = o.session_name;
		size_t i = 0;
		if (n) {
			for (; i + 1 < NAME_MAX_CH && n[i]; i++)
				m->name[i] = (wchar_t)(unsigned char)n[i];
			m->name[i] = 0;
		} else {
			for (; i + 1 < NAME_MAX_CH && DEFAULT_NAME[i]; i++)
				m->name[i] = DEFAULT_NAME[i];
			m->name[i] = 0;
		}
	}

	if (kofw_ring_init(&m->ring, o.ring_capacity) != 0) {
		free(m);
		if (err) *err = KOFW_ERR_MEM;
		return NULL;
	}

	m->qprops_sz = props_bytes();
	m->qprops    = calloc(1, m->qprops_sz);
	m->wake      = CreateEventW(NULL, FALSE, FALSE, NULL);
	if (!m->qprops || !m->wake) {
		rc = KOFW_ERR_MEM;
		goto fail;
	}

	rc = start_session(m, &o);
	if (rc)
		goto fail;

	rc = enable_providers(m, o.providers ? o.providers : KOFW_SUB_PROCESS);
	if (rc)
		goto fail_session;

	rc = open_consumer(m);
	if (rc)
		goto fail_session;

	m->thread = CreateThread(NULL, 0, consume, m, 0, NULL);
	if (!m->thread) {
		CloseTrace(m->consumer);
		m->consumer = 0;
		rc = KOFW_ERR_THREAD;
		goto fail_session;
	}

	return m;

fail_session:
	if (m->session) {
		EVENT_TRACE_PROPERTIES *p = props_new(m->name, 0, 0, 0, 0);
		if (p) {
			(void)ControlTraceW(m->session, NULL, p,
					    EVENT_TRACE_CONTROL_STOP);
			free(p);
		}
		m->session = 0;
	}
fail:
	if (m->wake)
		CloseHandle(m->wake);
	free(m->qprops);
	kofw_ring_free(&m->ring);
	free(m);
	if (err)
		*err = rc;
	return NULL;
}

/* ---------------------------------------------------------------- draining */

int kofw_mon_next(struct kofw_mon *m, struct kofw_evt *out, uint32_t wait_ms)
{
	uint32_t left = wait_ms;

	if (!m || !out)
		return 0;

	for (;;) {
		/*
		 * Drain and filter in one loop, because a refused record must
		 * not consume the caller's wait: a scoped trace on a busy
		 * machine refuses almost everything, and returning "nothing
		 * yet" after each one would make it look idle while its own
		 * subtree was running.
		 */
		while (kofw_ring_take(&m->ring, out)) {
			/* Before the filter, so a refused record is not
			 * mistaken for a lost one. */
			if (!m->seq_started) {
				m->seq_started = 1;
				m->seq_expect  = out->seq;
			}
			if (out->seq > m->seq_expect)
				m->seq_gaps += out->seq - m->seq_expect;
			m->seq_expect = out->seq + 1u;

			if (kofw_filter_apply(&m->ptab, &m->filter, out))
				return 1;
			m->filtered++;
		}
		if (left == 0)
			return 0;

		/*
		 * Capped rather than waiting the whole remainder at once. The
		 * producer only signals on the empty-to-nonempty edge, and it
		 * decides that from a tail it may have read a moment stale - so
		 * a missed wakeup is possible and must cost latency instead of a
		 * hang.
		 */
		{
			DWORD slice = left < 50u ? left : 50u;
			(void)WaitForSingleObject(m->wake, slice);
			left -= slice;
		}
	}
}

void kofw_mon_health(struct kofw_mon *m, struct kofw_health *h)
{
	if (!m || !h)
		return;

	memset(h, 0, sizeof *h);
	h->produced       = atomic_load_explicit(&m->ring.produced,
						 memory_order_relaxed);
	h->ring_dropped   = atomic_load_explicit(&m->ring.dropped,
						 memory_order_relaxed);
	h->ring_high_water = atomic_load_explicit(&m->ring.high_water,
						  memory_order_relaxed);
	h->decode_failed  = atomic_load_explicit(&m->decode_failed,
						 memory_order_relaxed) +
			    m->schema.learn_failed;
	h->schema_full    = m->schema.cache_full;
	h->skipped_self   = atomic_load_explicit(&m->skipped_self,
						 memory_order_relaxed);
	h->filtered       = m->filtered;
	h->untracked      = m->ptab.overflow;
	h->seq_gaps       = m->seq_gaps;
	h->sub_asked      = m->sub_asked;
	h->sub_enabled    = m->sub_enabled;

	/*
	 * ETW's own losses, asked for rather than accumulated: the session keeps
	 * these counters and a consumer has no other way to learn about a record
	 * that was discarded before it was ever delivered.
	 */
	if (m->qprops && m->session) {
		memset(m->qprops, 0, m->qprops_sz);
		m->qprops->Wnode.BufferSize    = m->qprops_sz;
		m->qprops->Wnode.Flags         = WNODE_FLAG_TRACED_GUID;
		m->qprops->LoggerNameOffset    =
			(ULONG)sizeof(EVENT_TRACE_PROPERTIES);
		m->qprops->LogFileNameOffset   = 0;

		if (ControlTraceW(m->session, NULL, m->qprops,
				  EVENT_TRACE_CONTROL_QUERY) == ERROR_SUCCESS) {
			h->etw_events_lost  = m->qprops->EventsLost;
			h->etw_buffers_lost = m->qprops->LogBuffersLost;
			h->etw_rt_buf_lost  = m->qprops->RealTimeBuffersLost;
		}
	}
}

void kofw_mon_filter(struct kofw_mon *m, const struct kofw_filter *f)
{
	if (!m)
		return;
	if (f)
		m->filter = *f;
	else
		memset(&m->filter, 0, sizeof m->filter);
}

int kofw_mon_track(struct kofw_mon *m, uint32_t pid, const char *image)
{
	struct kofw_pent *p;

	if (!m)
		return -1;
	/* Never recycling here: this entry IS the root of a tracked tree, and
	 * losing it would silently unscope the whole trace. */
	p = kofw_ptab_add(&m->ptab, pid, 0, image, 0);
	if (!p)
		return -1;
	if (!p->tracked) {
		p->tracked = 1;
		m->ptab.n_alive_tracked++;
	}
	return 0;
}

uint32_t kofw_mon_tracked_alive(const struct kofw_mon *m)
{
	return m ? m->ptab.n_alive_tracked : 0;
}

const char *kofw_mon_name_of(struct kofw_mon *m, uint32_t pid,
			     uint64_t create_time)
{
	struct kofw_pent *p;

	if (!m)
		return "";
	p = kofw_ptab_of(&m->ptab, pid, create_time);
	return p ? p->image : "";
}

size_t kofw_mon_describe(struct kofw_mon *m, char *buf, size_t cap)
{
	if (!m)
		return 0;
	return kofw_schema_describe(&m->schema, buf, cap);
}

void kofw_mon_close(struct kofw_mon *m)
{
	if (!m)
		return;

	/*
	 * ORDER MATTERS AND THIS IS THE ORDER.
	 *
	 * Stopping the session is what makes ProcessTrace return; the flag makes
	 * the buffer callback agree at the next boundary. Only once that thread
	 * has actually exited is CloseTrace safe - calling it while ProcessTrace
	 * is running is defined but returns ERROR_CTX_CLOSE_PENDING, and a
	 * caller that treats that as done frees the context the callback is
	 * still being handed.
	 */
	m->stopping = 1;

	if (m->session) {
		EVENT_TRACE_PROPERTIES *p = props_new(m->name, 0, 0, 0, 0);
		if (p) {
			(void)ControlTraceW(m->session, NULL, p,
					    EVENT_TRACE_CONTROL_STOP);
			free(p);
		}
		m->session = 0;
	}

	if (m->thread) {
		(void)WaitForSingleObject(m->thread, 10000);
		CloseHandle(m->thread);
		m->thread = NULL;
	}

	if (m->consumer) {
		CloseTrace(m->consumer);
		m->consumer = 0;
	}

	if (m->wake)
		CloseHandle(m->wake);
	free(m->qprops);
	kofw_ring_free(&m->ring);
	free(m);
}
