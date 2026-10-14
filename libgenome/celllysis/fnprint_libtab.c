/*
 * fnprint_libtab.c - the known-library window table, the vote over a function's bytes, the
 * byte statistics that call a chunk data, and the sketch of a unit.
 *
 * WHY THIS IS THE EXCLUSION GROUND. Every other signal that says "library" (a symbol's name, a marker
 * string, the layout, the shape of the entry stub, a size, a raw kernel entry) can be changed by an
 * author who patches the file and leaves the function's own bytes alone: rename it, strip it,
 * rewrite the string, reorder the link, put his code behind a prologue that looks like libc's. Taking
 * code out of the evidence on such a signal is a blind spot the adversary steers. A window of bytes
 * that is in a table built from library bytes is library by what it IS: to make an author window
 * match, the author has to write library bytes, and a payload inside a library function keeps its own
 * windows out of the table, so the payload remains evidence.
 *
 * COST. One rolling pass over the bytes (the same iterator as the block similarity, so the same
 * value) and one probe of an open-addressing table per window - or per sampled window. The probe of
 * the stream pass (fnprint_wpass.c) is made only for the windows that already passed the database's
 * cheap rejects, which is a few in a hundred.
 */
#include "fnprint.h"

#include <stdlib.h>
#include <string.h>

#include <kofcmp.h>

#include "mutation_window.h"

static uint32_t slot_ix(uint32_t v, uint32_t lg)
{
	return (uint32_t)(v * 2654435769u) >> (32u - lg);
}

static uint32_t stored(uint32_t v)
{
	return v ? v : 1u;
}

int kgenome_fnprint_libtab_init(struct kgenome_fnprint_libtab *t, uint32_t sel_bits, struct kgenome_ledger *led)
{
	memset(t, 0, sizeof *t);
	t->sel_bits = sel_bits > 24u ? 24u : sel_bits;
	t->led = led;
	return 1;
}

void kgenome_fnprint_libtab_free(struct kgenome_fnprint_libtab *t)
{
	if (!t)
		return;
	if (t->led)
		kgenome_ledger_release(t->led, t->bytes);
	free(t->slot);
	memset(t, 0, sizeof *t);
}

int kgenome_fnprint_libtab_sampled(const struct kgenome_fnprint_libtab *t, uint32_t v)
{
	return t && (v & ((1u << t->sel_bits) - 1u)) == 0;
}

int kgenome_fnprint_libtab_has(const struct kgenome_fnprint_libtab *t, uint32_t v)
{
	uint32_t lg, i, s;

	if (!t || !t->cap || !kgenome_fnprint_libtab_sampled(t, v))
		return 0;
	lg = (uint32_t)__builtin_ctzll(t->cap);
	s = stored(v);
	for (i = slot_ix(v, lg);; i = (i + 1u) & (uint32_t)(t->cap - 1u)) {
		if (t->slot[i] == s)
			return 1;
		if (!t->slot[i])
			return 0;
	}
}

/* Grow to twice the capacity (or the first 4096 slots), charged; 0 when refused. */
static int grow(struct kgenome_fnprint_libtab *t)
{
	uint64_t ncap = t->cap ? t->cap * 2u : 4096u, i;
	uint32_t *ns;
	uint32_t lg;

	if (ncap > (1ull << 31))
		return 0;
	if (t->led && !kgenome_ledger_charge(t->led, ncap * sizeof *ns))
		return 0;
	ns = calloc((size_t)ncap, sizeof *ns);
	if (!ns) {
		if (t->led)
			kgenome_ledger_release(t->led, ncap * sizeof *ns);
		t->status = kgenome_status_merge(t->status, KGENOME_NOMEM);
		return 0;
	}
	lg = (uint32_t)__builtin_ctzll(ncap);
	for (i = 0; i < t->cap; i++) {
		uint32_t s = t->slot[i], j;

		if (!s)
			continue;
		for (j = slot_ix(s, lg);; j = (j + 1u) & (uint32_t)(ncap - 1u))
			if (!ns[j]) {
				ns[j] = s;
				break;
			}
	}
	if (t->led)
		kgenome_ledger_release(t->led, t->cap * sizeof *ns);
	free(t->slot);
	t->slot = ns;
	t->cap = ncap;
	t->bytes = ncap * sizeof *ns;
	return 1;
}

static void put(struct kgenome_fnprint_libtab *t, uint32_t v)
{
	uint32_t lg, i, s = stored(v);

	if ((t->n + 1u) * 2u > t->cap && !grow(t)) {
		if ((t->n + 1u) * 10u > t->cap * 9u || !t->cap) {
			t->n_refused++;
			t->status = kgenome_status_merge(t->status, KGENOME_OVER_BUDGET);
			return;
		}
	}
	lg = (uint32_t)__builtin_ctzll(t->cap);
	for (i = slot_ix(v, lg);; i = (i + 1u) & (uint32_t)(t->cap - 1u)) {
		if (t->slot[i] == s)
			return;
		if (!t->slot[i]) {
			t->slot[i] = s;
			t->n++;
			return;
		}
	}
}

int kgenome_fnprint_libtab_put(struct kgenome_fnprint_libtab *t, uint32_t v)
{
	uint64_t refused;

	if (!t || !kgenome_fnprint_libtab_sampled(t, v))
		return 0;
	refused = t->n_refused;
	t->n_seen++;
	put(t, v);
	return t->n_refused == refused;
}

void kgenome_fnprint_libtab_add(struct kgenome_fnprint_libtab *t, const uint8_t *p, uint64_t n)
{
	struct kgenome_mtn_win w;

	if (!t || !p || !kgenome_mtn_win_begin(&w, p, n, KGENOME_MUTATION_RAW))
		return;
	do {
		uint32_t v = kgenome_mtn_win_value(&w);

		if (!kgenome_fnprint_libtab_sampled(t, v) || kgenome_mtn_win_flat(&w))
			continue;
		t->n_seen++;
		put(t, v);
	} while (kgenome_mtn_win_next(&w));
}

void kgenome_fnprint_libvote(const struct kgenome_fnprint_libtab *t, const uint8_t *p, uint64_t n,
			     struct kgenome_fnprint_libvote *out)
{
	struct kgenome_mtn_win w;

	memset(out, 0, sizeof *out);
	if (!p || !kgenome_mtn_win_begin(&w, p, n, KGENOME_MUTATION_RAW))
		return;
	do {
		uint32_t v = kgenome_mtn_win_value(&w);

		if (kgenome_mtn_win_flat(&w))
			continue;
		out->n_win++;
		if (t && kgenome_fnprint_libtab_sampled(t, v)) {
			out->n_sampled++;
			out->n_hit += (uint32_t)kgenome_fnprint_libtab_has(t, v);
		}
	} while (kgenome_mtn_win_next(&w));
}

/* ---- the relocation mask ---------------------------------------------------------- */

/* One-byte opcodes that take a ModRM and may carry a RIP-relative operand; and the `0F xx` forms. */
static int op1_modrm(uint8_t b)
{
	switch (b) {
	case 0x8B: case 0x89: case 0x8D: case 0x3B: case 0x39: case 0x03: case 0x01: case 0x2B: case 0x29:
	case 0x0B: case 0x09: case 0x23: case 0x21: case 0x33: case 0x31: case 0x13: case 0x11: case 0x1B:
	case 0x19: case 0x85: case 0x84: case 0xFF: case 0xC7: case 0x83: case 0x80: case 0x81: case 0xF7:
	case 0xC6: case 0x38: case 0x3A: case 0x00: case 0x02: case 0x88: case 0x8A:
		return 1;
	}
	return 0;
}

static int op2_modrm(uint8_t b)
{
	switch (b) {
	case 0xB6: case 0xB7: case 0xBE: case 0xBF: case 0x10: case 0x11: case 0x28: case 0x29: case 0x6F:
	case 0x7F: case 0xAF: case 0xD6: case 0xEF: case 0xA3: case 0xAB: case 0xBA:
		return 1;
	}
	return 0;
}

static int rip_modrm(uint8_t m)
{
	return (m & 0xC7u) == 0x05u;
}

uint64_t kgenome_fnprint_relmask(const uint8_t *p, uint64_t n, uint8_t *out, uint64_t slack)
{
	uint64_t i, masked = 0, lo_ok = slack;
	int32_t d;

	if (out != p)
		memcpy(out, p, (size_t)n);
	for (i = 0; i + 5 <= n; i++) {
		uint8_t b = p[i];
		uint64_t at = 0, len = 0;

		if (b == 0xE8 || b == 0xE9) {
			at = i + 1; len = i + 5;
		} else if (b == 0x0F && i + 6 <= n && (p[i + 1] & 0xF0u) == 0x80u) {
			at = i + 2; len = i + 6;
		} else if (i + 6 <= n && rip_modrm(p[i + 1]) && op1_modrm(b)) {
			at = i + 2; len = i + 6;
		} else if (i + 7 <= n && b == 0x0F && op2_modrm(p[i + 1]) && rip_modrm(p[i + 2])) {
			at = i + 3; len = i + 7;
		} else {
			continue;
		}
		memcpy(&d, p + at, 4);
		{
			int64_t t = (int64_t)len + d;

			if (t < -(int64_t)lo_ok || t > (int64_t)(n + slack))
				continue;
		}
		memset(out + at, 0, 4);
		masked++;
		i = len - 1;                    /* the field is consumed: the next opcode starts after it */
	}
	return masked;
}

/* ---- byte statistics ----------------------------------------------------------- */

void kgenome_fnprint_bstat(const uint8_t *p, uint32_t n, struct kgenome_fnprint_bstat *out)
{
	uint32_t i, z = 0, a = 0, h = 0;

	for (i = 0; i < n; i++) {
		uint8_t b = p[i];

		z += b == 0;
		a += (uint32_t)((uint8_t)(b - 0x20u) < 0x5fu);
		h += b >= 0x80u;
	}
	out->n = n; out->zero = z; out->ascii = a; out->hi = h;
}

/*
 * DATA, by a bound that machine code does not reach: x86 code of any compiler has few printable-only
 * stretches and more than a few high bytes. 90% zeros (padding) or 85% printable with under 5% high
 * bytes. [Inference] alphanumeric shellcode is printable by design and would be called data: a skip
 * made on this is a blind spot an author can choose, which is why the stream pass never skips on it
 * unless the caller opts in and the skipped bytes are counted.
 */
int kgenome_fnprint_bstat_is_data(const struct kgenome_fnprint_bstat *s)
{
	if (!s->n)
		return 0;
	return (uint64_t)s->zero * 10u >= (uint64_t)s->n * 9u ||
	       ((uint64_t)s->ascii * 100u >= (uint64_t)s->n * 85u && (uint64_t)s->hi * 100u < (uint64_t)s->n * 5u);
}

/* ---- the sketch of a unit -------------------------------------------------------- */

uint32_t kgenome_fnprint_wsketch(const uint8_t *p, uint64_t n, const struct kgenome_fnprint_libtab *lib,
				 uint32_t *out, uint32_t k)
{
	struct kgenome_mtn_win w;
	uint32_t m = 0, i, mx = 0, mi = 0;

	if (!p || !out || !k || !kgenome_mtn_win_begin(&w, p, n, KGENOME_MUTATION_RAW))
		return 0;
	/* the k smallest distinct values: an unsorted buffer whose maximum is cached. Once it is full a
	 * window enters it rarely (the values are mixed), so the cost is one comparison per window. */
	do {
		uint32_t v = kgenome_mtn_win_value(&w);

		if (m == k && v >= mx)
			continue;
		if (kgenome_mtn_win_flat(&w) || (lib && kgenome_fnprint_libtab_has(lib, v)))
			continue;
		for (i = 0; i < m; i++)
			if (out[i] == v)
				break;
		if (i < m)
			continue;
		if (m < k) {
			out[m++] = v;
			if (m == k) {
				for (i = 0, mx = 0; i < m; i++)
					if (out[i] >= mx) { mx = out[i]; mi = i; }
			}
		} else {
			out[mi] = v;
			for (i = 0, mx = 0; i < m; i++)
				if (out[i] >= mx) { mx = out[i]; mi = i; }
		}
	} while (kgenome_mtn_win_next(&w));
	qsort(out, m, sizeof *out, kof_cmp_u32);
	return m;
}

/* ---- units from windows ------------------------------------------------------------ */

uint32_t kgenome_fnprint_runs(const uint8_t *p, uint64_t n, const struct kgenome_fnprint_libtab *lib,
			      uint32_t gap, uint32_t min_win, kgenome_fnprint_run_fn fn, void *user, uint32_t *dropped)
{
	struct kgenome_mtn_win w;
	uint64_t lo = 0, last = 0;
	uint32_t nw = 0, quiet = 0, offered = 0, drop = 0;
	int open = 0, stop = 0;

	if (dropped)
		*dropped = 0;
	if (!p || !fn || !kgenome_mtn_win_begin(&w, p, n, KGENOME_MUTATION_RAW))
		return 0;
	do {
		uint32_t v = kgenome_mtn_win_value(&w);

		if (kgenome_mtn_win_flat(&w))
			continue;
		if (lib && kgenome_fnprint_libtab_has(lib, v)) {
			quiet++;
			if (open && quiet > gap) {
				open = 0;
				if (nw >= min_win) {
					offered++;
					stop = fn(user, lo, last + KGENOME_MUTATION_NG - lo, nw);
				} else {
					drop++;
				}
			}
			continue;
		}
		if (!open) {
			open = 1; lo = w.at; nw = 0;
		}
		quiet = 0;
		nw++;
		last = w.at;
	} while (!stop && kgenome_mtn_win_next(&w));
	if (open && !stop) {
		if (nw >= min_win) {
			offered++;
			fn(user, lo, last + KGENOME_MUTATION_NG - lo, nw);
		} else {
			drop++;
		}
	}
	if (dropped)
		*dropped = drop;
	return offered;
}
