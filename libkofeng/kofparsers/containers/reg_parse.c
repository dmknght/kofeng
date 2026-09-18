/*
 * reg_parse.c - see reg_parse.h, and kofmod/reg.h for the format.
 *
 * ONE PASS OVER THE LINES, and the only thing that is not a line is a hex
 * value: it continues across as many as it likes behind a trailing backslash,
 * and that continuation is the one place a line-at-a-time reader would cut a
 * payload in half. It is handled where the value is claimed rather than by a
 * second pass, because the run has to be ONE region for a rule to match across
 * it.
 *
 * NOTHING IS DECODED. A hex(2) value expands to a command line and reading it
 * would be worth doing - but producing an object from bytes is an unpacker's
 * job and this is a parser. What this owes is the extent, so the hex runs are
 * their own region and whoever writes that unpacker has somewhere to start.
 */

#include <stddef.h>
#include <string.h>

#include "reg_parse.h"
#include "../runlist.h"

static const char MAGIC5[] = "Windows Registry Editor Version 5.00";
static const char MAGIC4[] = "REGEDIT4";

static int reg_space(uint8_t c)
{
	return c == ' ' || c == '\t' || c == '\r' || c == '\n';
}

/* The end of the line starting at `at` - the offset of its '\n', or f.n. */
static uint64_t line_end(kof_buf f, uint64_t at)
{
	while (at < f.n && f.p[at] != '\n')
		at++;
	return at;
}

/*
 * The first byte of the line that is not blank space.
 *
 * '\r' IS IN THE SET, and leaving it out was a real bug rather than a nicety:
 * line_end stops at '\n', so on a CRLF file a blank line is one byte long and
 * that byte is '\r'. Without this the caller saw a non-blank line whose first
 * character matched none of the four it knows, and every empty line in every
 * Windows-written .reg raised JUNK_LINE - which is to say, the anomaly fired
 * on the format's own normal shape.
 */
static uint64_t line_text(kof_buf f, uint64_t at, uint64_t end)
{
	while (at < end && (f.p[at] == ' ' || f.p[at] == '\t' ||
			    f.p[at] == '\r'))
		at++;
	return at;
}

/*
 * Does the version line sit at `at`, allowing for a UTF-8 BOM in front of it?
 *
 * THE BOM IS NOT SKIPPED SILENTLY ELSEWHERE, only here: it is three bytes
 * before the first line and it belongs to the header region either way, so
 * measuring the header from offset zero keeps the partition exact without the
 * rest of the parser knowing the bytes are there.
 */
static uint64_t reg_magic_at(kof_buf f)
{
	uint64_t at = 0;

	if (f.n >= 3u && f.p[0] == 0xEFu && f.p[1] == 0xBBu && f.p[2] == 0xBFu)
		at = 3u;
	return at;
}

int kof_reg_sniff(kof_buf file)
{
	uint64_t at;

	if (!file.p)
		return 0;
	at = reg_magic_at(file);
	/*
	 * THE VERSION LINE AND NOTHING ELSE. regedit itself refuses a file
	 * whose first line is not one of these two, so matching what the
	 * importer matches is both the strictest test available and the
	 * correct one - a .reg without it is a file Windows would not apply.
	 */
	if (file.n >= at + sizeof MAGIC5 - 1u &&
	    memcmp(file.p + at, MAGIC5, sizeof MAGIC5 - 1u) == 0)
		return 1;
	return file.n >= at + sizeof MAGIC4 - 1u &&
	       memcmp(file.p + at, MAGIC4, sizeof MAGIC4 - 1u) == 0;
}

/* In enum kof_reg_class order, which is what kof_runs_resolve indexes by. */
static const uint32_t reg_cls_bit[KOF_REG_CLS_COUNT] = {
	KOF_SCAN_REG_HEADER,
	KOF_SCAN_REG_KEYS,
	KOF_SCAN_REG_VALUES,
	KOF_SCAN_REG_HEX,
	KOF_SCAN_REG_COMMENT
};

static uint32_t reg_resolve_scan(const struct kof_obj_ctx *ctx, uint32_t mask,
				 struct kof_range *out, uint32_t max_out)
{
	const struct kof_reg_info *r =
		(const struct kof_reg_info *)ctx->file_header;

	if (!r || !r->valid || !out || max_out == 0)
		return 0;
	_Static_assert(sizeof r->run[0] == sizeof(struct kof_run),
		       "the view's run and runlist.h's have drifted apart");
	return kof_runs_resolve((const struct kof_run *)r->run, r->n_runs, mask,
				reg_cls_bit, KOF_SCAN_REG_UNCLAIMED,
				ctx->obj_size, out, max_out);
}

/*
 * WHERE A VALUE'S DATA ENDS, which is the end of its line unless the data is
 * hex and the line ends in a backslash.
 *
 * `hex_from` comes back as the offset of the first hex digit when this was a
 * hex value, so the caller can claim that run separately - it is the part a
 * payload would be in, and the part an unpacker will want.
 */
static uint64_t value_end(kof_buf f, uint64_t at, uint64_t end,
			  uint64_t *hex_from)
{
	uint64_t eq = at;

	*hex_from = 0;
	/*
	 * The '=' that separates the name from the data, found OUTSIDE the
	 * quoted name: a value called "a=b" is legal and its quotes are what
	 * say so.
	 */
	if (at < end && f.p[at] == '"') {
		eq = at + 1u;
		while (eq < end && f.p[eq] != '"') {
			if (f.p[eq] == '\\' && eq + 1u < end)
				eq++;          /* an escaped quote or slash */
			eq++;
		}
		if (eq >= end)
			return end;
		eq++;                          /* past the closing quote */
	} else if (at < end && f.p[at] == '@') {
		eq = at + 1u;
	} else {
		return end;
	}
	eq = line_text(f, eq, end);
	if (eq >= end || f.p[eq] != '=')
		return end;
	eq++;

	if (eq + 4u <= end && memcmp(f.p + eq, "hex", 3u) == 0) {
		uint64_t colon = eq + 3u;

		/* hex:, or hex(2): and friends. */
		if (colon < end && f.p[colon] == '(')
			while (colon < end && f.p[colon] != ')')
				colon++;
		while (colon < end && f.p[colon] != ':')
			colon++;
		if (colon < end) {
			uint64_t stop = end;

			*hex_from = colon + 1u;
			/*
			 * A TRAILING BACKSLASH CONTINUES THE VALUE, and the
			 * loop below is the only place this parser is not
			 * line oriented. A run cut at the first newline would
			 * split an embedded payload across two regions, which
			 * is the one way to make a region useless to a rule.
			 */
			for (;;) {
				uint64_t last = stop;

				while (last > *hex_from &&
				       reg_space(f.p[last - 1u]))
					last--;
				if (last == 0 || f.p[last - 1u] != '\\')
					return stop;
				stop = line_end(f, stop + 1u);
				if (stop >= f.n)
					return f.n;
			}
		}
	}
	return end;
}

int kof_reg_parse(kof_buf file, struct kof_reg_info *info,
		  struct kof_obj_ctx *ctx)
{
	struct kof_runs runs;
	uint64_t at;

	if (!file.p || !info || !ctx)
		return 0;
	memset(info, 0, sizeof *info);
	info->version = KOF_REG_INFO_VERSION;

	if (!kof_reg_sniff(file)) {
		info->anomalies |= KOF_REG_ANOM_NO_HEADER;
		return 0;
	}
	kof_runs_init(&runs, (struct kof_run *)info->run, KOF_REG_MAX_EXTENTS,
		      KOF_REG_CLS_COUNT);

	at = reg_magic_at(file);
	if (at + sizeof MAGIC4 - 1u <= file.n &&
	    memcmp(file.p + at, MAGIC4, sizeof MAGIC4 - 1u) == 0)
		info->anomalies |= KOF_REG_ANOM_OLD_FORMAT;

	/* The header is the version line, counted from zero so a BOM belongs
	 * to it rather than to nothing. */
	{
		uint64_t end = line_end(file, at);

		kof_runs_add(&runs, file.n, 0, end < file.n ? end + 1u : end,
			     KOF_REG_CLS_HEADER);
		at = end < file.n ? end + 1u : file.n;
	}

	while (at < file.n) {
		uint64_t end = line_end(file, at);
		uint64_t t = line_text(file, at, end);
		uint64_t next = end < file.n ? end + 1u : file.n;

		if (t >= end) {
			at = next;                 /* a blank line */
			continue;
		}
		if (file.p[t] == ';') {
			kof_runs_add(&runs, file.n, at, next - at,
				     KOF_REG_CLS_COMMENT);
			at = next;
			continue;
		}
		if (file.p[t] == '[') {
			kof_runs_add(&runs, file.n, at, next - at,
				     KOF_REG_CLS_KEYS);
			info->n_keys++;
			/*
			 * "[-HKEY..." IS A DELETION, and the minus is the
			 * whole of the difference. Counted rather than judged:
			 * an uninstaller deletes keys and so does everything
			 * that turns a protection off, and WHICH key decides
			 * between them - which is why the key lines are a
			 * region of their own.
			 */
			if (t + 1u < end && file.p[t + 1u] == '-') {
				info->n_deletes++;
				info->anomalies |= KOF_REG_ANOM_DELETES;
			}
			at = next;
			continue;
		}
		if (file.p[t] == '"' || file.p[t] == '@') {
			uint64_t hex_from = 0;
			uint64_t vend = value_end(file, t, end, &hex_from);

			if (vend < end)
				vend = end;
			info->n_values++;
			if (hex_from && hex_from < vend) {
				uint64_t hn = vend - hex_from;

				/* The name and the "hex(n):" in front of the
				 * digits stay VALUES; only the digits are HEX,
				 * so a rule matching on data is not matching
				 * on the word that introduced it. */
				kof_runs_add(&runs, file.n, at, hex_from - at,
					     KOF_REG_CLS_VALUES);
				kof_runs_add(&runs, file.n, hex_from, hn,
					     KOF_REG_CLS_HEX);
				info->n_hex++;
				if (hn > info->hex_longest)
					info->hex_longest = hn;
				if (hn > KOF_REG_HEX_LONG)
					info->anomalies |=
						KOF_REG_ANOM_HEX_LONG;
				at = vend < file.n ? vend + 1u : file.n;
				continue;
			}
			kof_runs_add(&runs, file.n, at, next - at,
				     KOF_REG_CLS_VALUES);
			/* "Name"=- removes the value. */
			if (end > at + 1u && file.p[end - 1u] == '-' &&
			    end >= 2u && file.p[end - 2u] == '=') {
				info->n_deletes++;
				info->anomalies |= KOF_REG_ANOM_DELETES;
			} else if (end > at + 2u && file.p[end - 1u] == '\r' &&
				   file.p[end - 2u] == '-' &&
				   file.p[end - 3u] == '=') {
				info->n_deletes++;
				info->anomalies |= KOF_REG_ANOM_DELETES;
			}
			at = next;
			continue;
		}
		/*
		 * Anything else is a line regedit would have refused. Left
		 * UNCLAIMED rather than given a class: it is not a key, a
		 * value or a comment, and inventing a fourth thing for it
		 * would put junk in a region a rule reads as meaningful.
		 */
		info->anomalies |= KOF_REG_ANOM_JUNK_LINE;
		at = next;
	}

	kof_runs_settle(&runs, info->region_bytes);
	if (runs.full)
		info->anomalies |= KOF_REG_ANOM_EXTENTS_FULL;
	if (runs.overlapped)
		info->anomalies |= KOF_REG_ANOM_OVERLAP;
	info->n_runs = runs.n;
	info->valid = 1;

	ctx->obj_size     = file.n;
	ctx->format       = KOF_FMT_REG;
	ctx->file_header  = info;
	ctx->resolve_scan = reg_resolve_scan;
	return 1;
}

#define X_BIT(b)  (b),
#define X_CASE(b) case (b): return #b;

const uint32_t kof_reg_region_bits[] = { REG_REGIONS(X_BIT) };
_Static_assert(sizeof kof_reg_region_bits / sizeof kof_reg_region_bits[0] ==
	       KOF_REG_REGION_COUNT, "region list and its count disagree");

const char *kof_reg_region_name(uint32_t bit)
{
	switch (bit) {
	REG_REGIONS(X_CASE)
	default: return 0;
	}
}

#undef X_BIT
#undef X_CASE

const char *kof_reg_anomaly_name(unsigned index)
{
	static const char *const n[] = {
		"NO_HEADER", "OLD_FORMAT", "DELETES", "HEX_LONG",
		"EXTENTS_FULL", "OVERLAP", "JUNK_LINE"
	};

	_Static_assert(sizeof n / sizeof n[0] == KOF_REG_ANOM_COUNT,
		       "anomaly name table and its count disagree");
	return index < sizeof n / sizeof n[0] ? n[index] : 0;
}
