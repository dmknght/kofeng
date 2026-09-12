/*
 * wchan.c - see wchan.h.
 */

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdatomic.h>

#include <windows.h>

#include "kofchan.h"
#include "kofevtlog.h"

#define CHAN_CAP_MIN 1024u
#define CHAN_CAP_MAX (1u << 20)

struct kof_chan_pub {
	HANDLE h_data, h_cur, h_wake;
	struct kof_chan_hdr    *hdr;
	unsigned char           *rec;
	struct kof_chan_cursor *cur;
	uint32_t capacity, rec_size;
};

struct kof_chan_sub {
	HANDLE h_data, h_cur, h_wake;
	const struct kof_chan_hdr *hdr;
	const unsigned char        *rec;
	struct kof_chan_cursor    *cur;

	/*
	 * The same mapping as `hdr`, kept non-const for UnmapViewOfFile.
	 *
	 * The pointer everything READS through is const, because the data
	 * section is read-only and the type should say so. Unmapping needs a
	 * writable pointer, and casting the const away at the two teardown
	 * sites is how -Wcast-qual stops catching the casts that matter. One
	 * field, set once, used twice.
	 */
	void *hdr_raw;
};

/*
 * The three object names, derived from one base so a caller names the channel
 * once. Local\ rather than Global\ - see the note in wchan.h on what that
 * contains and what it does not.
 */
static int chan_names(const char *base, wchar_t *d, wchar_t *c, wchar_t *w,
		      size_t cap)
{
	static const wchar_t pre[] = L"Local\\";
	const char *b = (base && *base) ? base : KOF_CHAN_NAME;
	wchar_t stem[192];
	size_t i = 0, o = 0;

	for (; pre[i] && o + 1 < sizeof stem / sizeof stem[0]; i++)
		stem[o++] = pre[i];
	for (i = 0; b[i] && o + 1 < sizeof stem / sizeof stem[0]; i++)
		stem[o++] = (wchar_t)(unsigned char)b[i];
	stem[o] = 0;

	if (o + 8 >= cap)
		return 0;
	{
		static const wchar_t sd[] = L".data";
		static const wchar_t sc[] = L".cur";
		static const wchar_t sw[] = L".wake";
		size_t k;

		for (k = 0; k <= o; k++)
			d[k] = c[k] = w[k] = stem[k];
		for (k = 0; sd[k]; k++) d[o + k] = sd[k];
		d[o + k] = 0;
		for (k = 0; sc[k]; k++) c[o + k] = sc[k];
		c[o + k] = 0;
		for (k = 0; sw[k]; k++) w[o + k] = sw[k];
		w[o + k] = 0;
	}
	return 1;
}

static uint32_t round_pow2(uint32_t v)
{
	uint32_t p = CHAN_CAP_MIN;

	while (p < v && p < CHAN_CAP_MAX)
		p <<= 1;
	return p;
}

/* ---------------------------------------------------------------- publish */

struct kof_chan_pub *kof_chan_publish_open(const char *name,
					     uint32_t capacity)
{
	wchar_t nd[256], nc[256], nw[256];
	struct kof_chan_pub *p;
	uint64_t bytes;
	uint32_t cap = round_pow2(capacity ? capacity : 8192u);

	if (!chan_names(name, nd, nc, nw, 256))
		return NULL;

	p = calloc(1, sizeof *p);
	if (!p)
		return NULL;
	p->capacity = cap;
	p->rec_size = (uint32_t)sizeof(struct kof_evt);
	bytes = sizeof(struct kof_chan_hdr) +
		(uint64_t)cap * p->rec_size;

	p->h_data = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL,
				       PAGE_READWRITE,
				       (DWORD)(bytes >> 32),
				       (DWORD)(bytes & 0xffffffffu), nd);
	/*
	 * REFUSED IF IT ALREADY EXISTS, rather than attached.
	 *
	 * Two publishers on one ring interleave into it and the records that
	 * come out belong to neither. It is also the shape of a squatting
	 * attack: something that created the section first would otherwise
	 * have the sensor write every event into a mapping it controls.
	 */
	if (!p->h_data || GetLastError() == ERROR_ALREADY_EXISTS)
		goto fail;

	p->h_cur = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL,
				      PAGE_READWRITE, 0,
				      (DWORD)sizeof(struct kof_chan_cursor),
				      nc);
	if (!p->h_cur || GetLastError() == ERROR_ALREADY_EXISTS)
		goto fail;

	p->h_wake = CreateEventW(NULL, FALSE, FALSE, nw);
	if (!p->h_wake)
		goto fail;

	p->hdr = MapViewOfFile(p->h_data, FILE_MAP_WRITE, 0, 0, 0);
	p->cur = MapViewOfFile(p->h_cur, FILE_MAP_WRITE, 0, 0, 0);
	if (!p->hdr || !p->cur)
		goto fail;

	p->rec = (unsigned char *)p->hdr + sizeof *p->hdr;

	memset(p->hdr, 0, sizeof *p->hdr);
	p->hdr->rec_size  = p->rec_size;
	p->hdr->head_size = (uint32_t)KOF_EVT_HEAD;
	p->hdr->len_off   = (uint32_t)offsetof(struct kof_evt, text_len);
	p->hdr->rec_kind  = KOFEVT_REC_KOF;
	p->hdr->capacity  = cap;
	p->hdr->pid       = GetCurrentProcessId();
	p->hdr->version   = KOF_CHAN_VERSION;
	/*
	 * The magic LAST, and with a release, so a subscriber that sees it sees
	 * every field above it. Written first, a subscriber could attach to a
	 * header whose capacity was still zero and index a ring of no slots.
	 */
	atomic_store_explicit((_Atomic uint32_t *)&p->hdr->magic,
			      KOF_CHAN_MAGIC, memory_order_release);
	return p;

fail:
	if (p->hdr) UnmapViewOfFile(p->hdr);
	if (p->cur) UnmapViewOfFile(p->cur);
	if (p->h_wake) CloseHandle(p->h_wake);
	if (p->h_cur)  CloseHandle(p->h_cur);
	if (p->h_data) CloseHandle(p->h_data);
	free(p);
	return NULL;
}

int kof_chan_publish(struct kof_chan_pub *p, const struct kof_evt *e)
{
	uint32_t h, t, depth;

	if (!p || !e)
		return -1;

	h = p->hdr->head;
	/*
	 * THE TAIL IS NOT TRUSTED.
	 *
	 * It is written by the subscriber, which is the lower-privilege half
	 * and may be compromised or merely wrong. An out-of-range value would
	 * otherwise make this overwrite live slots or compute a depth that
	 * wraps - so it is clamped to a ring's worth and nothing else is
	 * assumed about it. A bogus tail costs that subscriber its own events.
	 */
	t = atomic_load_explicit((_Atomic uint32_t *)&p->cur->tail,
				 memory_order_acquire);
	depth = h - t;
	if (depth > p->capacity)
		depth = p->capacity;

	if (depth >= p->capacity) {
		p->hdr->dropped++;
		return 1;
	}

	memcpy(p->rec + (uint64_t)(h & (p->capacity - 1u)) * p->rec_size,
	       e, p->rec_size);
	p->hdr->produced++;

	/* RELEASE: publishes the record above, so a subscriber that acquires
	 * this head sees a complete one rather than a half-written one. */
	atomic_store_explicit((_Atomic uint32_t *)&p->hdr->head, h + 1u,
			      memory_order_release);

	/* Woken on the empty-to-nonempty edge only, so a burst costs one
	 * syscall rather than one per record. A missed edge costs latency, not
	 * a stall: the subscriber caps every wait. */
	if (depth == 0)
		SetEvent(p->h_wake);
	return 0;
}

void kof_chan_publish_close(struct kof_chan_pub *p)
{
	if (!p)
		return;
	/* Zero the magic first: a subscriber attaching during teardown must
	 * not find a header that describes a mapping about to go away. */
	if (p->hdr)
		atomic_store_explicit((_Atomic uint32_t *)&p->hdr->magic, 0u,
				      memory_order_release);
	if (p->hdr) UnmapViewOfFile(p->hdr);
	if (p->cur) UnmapViewOfFile(p->cur);
	if (p->h_wake) CloseHandle(p->h_wake);
	if (p->h_cur)  CloseHandle(p->h_cur);
	if (p->h_data) CloseHandle(p->h_data);
	free(p);
}

/* -------------------------------------------------------------- subscribe */

struct kof_chan_sub *kof_chan_sub_open(const char *name, const char **why)
{
	wchar_t nd[256], nc[256], nw[256];
	struct kof_chan_sub *s;

	if (why)
		*why = "";
	if (!chan_names(name, nd, nc, nw, 256)) {
		if (why) *why = "the channel name is too long";
		return NULL;
	}

	s = calloc(1, sizeof *s);
	if (!s)
		return NULL;

	/*
	 * FILE_MAP_READ on the data, FILE_MAP_WRITE on the cursor, and that
	 * asymmetry is the point - see wchan.h. A subscriber cannot write a
	 * record because it does not hold the access to, not because it has
	 * been asked not to.
	 */
	s->h_data = OpenFileMappingW(FILE_MAP_READ, FALSE, nd);
	if (!s->h_data) {
		if (why) *why = "no sensor is publishing";
		goto fail;
	}
	s->h_cur = OpenFileMappingW(FILE_MAP_WRITE, FALSE, nc);
	if (!s->h_cur) {
		if (why) *why = "the cursor is not there";
		goto fail;
	}
	s->h_wake = OpenEventW(SYNCHRONIZE, FALSE, nw);

	s->hdr_raw = MapViewOfFile(s->h_data, FILE_MAP_READ, 0, 0, 0);
	s->hdr     = s->hdr_raw;
	s->cur = MapViewOfFile(s->h_cur, FILE_MAP_WRITE, 0, 0, 0);
	if (!s->hdr || !s->cur) {
		if (why) *why = "cannot map the channel";
		goto fail;
	}

	if (atomic_load_explicit((_Atomic uint32_t *)s->hdr_raw,
				 memory_order_acquire) != KOF_CHAN_MAGIC) {
		if (why) *why = "not a kofgrille channel";
		goto fail;
	}
	if (s->hdr->version != KOF_CHAN_VERSION) {
		if (why) *why = "a channel version this build does not know";
		goto fail;
	}
	/*
	 * The check the header exists for. A record of a different size decodes
	 * every field from the wrong offset; one of a different KIND decodes at
	 * the right offsets and means something else. Both are refused.
	 */
	if (s->hdr->rec_size != (uint32_t)sizeof(struct kof_evt)) {
		if (why) *why = "the sensor's record is a different size";
		goto fail;
	}
	if (s->hdr->rec_kind != KOFEVT_REC_KOF) {
		if (why) *why = "the sensor publishes a different record";
		goto fail;
	}
	if (s->hdr->capacity == 0u ||
	    (s->hdr->capacity & (s->hdr->capacity - 1u)) != 0u) {
		if (why) *why = "the channel capacity is not a power of two";
		goto fail;
	}

	s->rec = (const unsigned char *)s->hdr + sizeof *s->hdr;
	return s;

fail:
	if (s->hdr_raw) UnmapViewOfFile(s->hdr_raw);
	if (s->cur) UnmapViewOfFile(s->cur);
	if (s->h_wake) CloseHandle(s->h_wake);
	if (s->h_cur)  CloseHandle(s->h_cur);
	if (s->h_data) CloseHandle(s->h_data);
	free(s);
	return NULL;
}

const struct kof_chan_hdr *kof_chan_sub_header(const struct kof_chan_sub *s)
{
	return s ? s->hdr : NULL;
}

int kof_chan_next(struct kof_chan_sub *s, struct kof_evt *out,
		   uint32_t wait_ms)
{
	uint32_t left = wait_ms;

	if (!s || !out)
		return 0;

	for (;;) {
		uint32_t t = s->cur->tail;
		uint32_t h = atomic_load_explicit(
			(_Atomic uint32_t *)((unsigned char *)s->hdr_raw +
				offsetof(struct kof_chan_hdr, head)),
			memory_order_acquire);

		if (h != t) {
			/*
			 * A PUBLISHER THAT LAPPED US.
			 *
			 * If more than a ring's worth arrived since the last
			 * read, the oldest slots have been overwritten and
			 * reading from `tail` would hand back a record that is
			 * half old and half new. Skip forward to the oldest
			 * slot that is still intact: the loss already happened
			 * and is counted in the header - what must not happen
			 * is reporting a spliced record as an event.
			 */
			if (h - t > s->hdr->capacity)
				t = h - s->hdr->capacity;

			memcpy(out, s->rec + (uint64_t)(t & (s->hdr->capacity -
							     1u)) *
					     s->hdr->rec_size,
			       sizeof *out);

			/* RELEASE, so the publisher cannot begin overwriting
			 * the slot until the copy above has happened. */
			atomic_store_explicit(
				(_Atomic uint32_t *)&s->cur->tail, t + 1u,
				memory_order_release);
			return 1;
		}

		if (left == 0)
			return 0;
		{
			DWORD slice = left < 50u ? left : 50u;

			/* Capped: the publisher signals only on the
			 * empty-to-nonempty edge and decides that from a tail
			 * it may have read a moment stale, so a missed wakeup
			 * must cost latency and not a hang. */
			if (s->h_wake)
				(void)WaitForSingleObject(s->h_wake, slice);
			else
				Sleep(slice);
			left -= slice;
		}
	}
}

void kof_chan_sub_close(struct kof_chan_sub *s)
{
	if (!s)
		return;
	if (s->hdr_raw) UnmapViewOfFile(s->hdr_raw);
	if (s->cur) UnmapViewOfFile(s->cur);
	if (s->h_wake) CloseHandle(s->h_wake);
	if (s->h_cur)  CloseHandle(s->h_cur);
	if (s->h_data) CloseHandle(s->h_data);
	free(s);
}
