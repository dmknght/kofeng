#define _GNU_SOURCE
#include "kv.h"

#define DIS_MAX_INSN 16u        /* the longest x86 instruction */


/*
 * How far back to look for an instruction boundary. See dis_sync.
 *
 * Sixty-four bytes is far more than x86 needs: a stream re-synchronises within a
 * handful of instructions, and the longest instruction there is is fifteen
 * bytes. It is a window rather than the whole region because the region can be
 * megabytes and this runs once a frame.
 */
#define DIS_RESYNC 64u



/*
 * What the heuristic makes of this object.
 *
 * One place, because two would drift: the dashboard and the status line show
 * the same verdict and a reader who saw them disagree would have no way to tell
 * which was lying. Scored here rather than read back from the scan, because the
 * scan may have had the heuristic switched off, and a screen that showed
 * nothing then would be reporting the option rather than the object.
 *
 * Returns 0 when no model covers this format, which is not the same as a score
 * of zero and must not be shown as one.
 */
/*
 * What the heuristic made of this object.
 *
 * A read, not a computation. The engine scored it while it was scanning, on the
 * object it had in front of it, with facts a viewer cannot see - which unpacker
 * produced which child, and whether that unpacker was a packer or a container.
 * Everything this file needs is in the result it was handed.
 *
 * Returns 0 when the heuristic did not run or no model covers this format,
 * which is not the same as a score of zero and must not be shown as one.
 */
int heur_of(const struct object *ob, struct kof_heur_facts *out,
		   int32_t *score, const char **guess)
{
	const struct kof_heur_model *hm = kof_heur_default();

	memset(out, 0, sizeof *out);
	out->format       = ob->ctx.format;
	out->anomalies    = ob->heur.heur_anomalies;
	out->flags        = ob->heur.heur_flags;
	*score = ob->heur.heur_score;
	*guess = "Unknown";
	if (!ob->heur.heur_scored)
		return 0;
	/*
	 * Re-run only to recover the WORD, which the result does not carry: the
	 * score is the engine's and is used as given, and this asks the same
	 * model the engine used which trace weighed most. Reading a model to
	 * name a number is not recomputing the number.
	 */
	{
		int32_t ignored = 0;

		kof_heur_score(hm, out, &ignored, guess);
	}
	return 1;
}

/* Would a scan report this object on the heuristic alone. */
int heur_reports(const struct object *ob, int32_t *score,
			const char **guess)
{
	struct kof_heur_facts hf;

	if (!heur_of(ob, &hf, score, guess))
		return 0;
	return *score >= kof_heur_default()->bar_centinats;
}

/* The mode to start in: what the object says, or 64 when it says nothing. */
static int dis_default_bits(struct view *v)
{
	struct object *ob = cur_obj(v);

	/*
	 * A PAYLOAD'S WIDTH IS ITS OWN, not its parent's - and it is already
	 * written down.
	 *
	 * A 64-bit ELF routinely carries a 32-bit payload, and decoding one at
	 * the wrong width is not a near miss: `53` reads as PUSH rbx instead of
	 * PUSH ebx, and `60` - PUSHAD, which 64-bit mode does not have at all -
	 * comes out as "(data)".
	 *
	 * So this used to special-case a payload child and ask sc_bits. That
	 * was wrong twice over. It is a THIRD place deciding a fact the finder
	 * already decided and kofscfind_image already wrote into the
	 * derived image's header - and it was handed `ob->buf.p`, which BEGINS
	 * WITH THAT HEADER, so it never matched a stub prologue and every
	 * payload came out 64.
	 *
	 * The parse of that header is the answer, for a payload child exactly
	 * as for any other object - and once the payload became an object with
	 * a header of its own, "a payload with no header" stopped existing, so
	 * the last resort went with it. sc_bits read four stub prologues to
	 * guess a width; four measured byte patterns answering a question the
	 * header already answers in a field.
	 */
	if (ob && ob->fmt) {
		if (ob->ctx.arch == KGENOME_ARCH_X86)
			return 32;
		if (ob->ctx.arch == KGENOME_ARCH_X86_64)
			return 64;
	}
	return 64;
}

/*
 * Gather up to n bytes of the region at `at` into buf, stopping at the end.
 *
 * Byte at a time through view_map, because a region is a list of extents and an
 * instruction may sit across the join between two of them. Reading the parent's
 * buffer directly would be faster and would decode bytes that are not adjacent
 * in this region at all.
 */
static unsigned dis_gather(struct view *v, uint64_t at, uint8_t *buf, unsigned n)
{
	uint64_t bn = 0;
	const uint8_t *bp = view_bytes(v, &bn);
	unsigned k = 0;

	if (!bp)
		return 0;
	while (k < n && at + k < v->rgn_len) {
		uint64_t fo = view_map(v, at + k, 0);

		if (fo >= bn)
			break;
		buf[k++] = bp[fo];
	}
	return k;
}

/*
 * Where the panel starts reading.
 *
 * A pinned range starts where it was pinned. An unpinned one follows the HEX
 * SELECTION when there is one, and the hex scroll when there is not - and the
 * selection has to win, because the two panes hold very different amounts. The
 * hex pane shows seventeen rows of sixteen bytes; the panel shows seventeen
 * INSTRUCTIONS, which is rarely more than sixty bytes. Starting both at the top
 * of the scroll meant selecting a byte anywhere below the first few hex rows
 * lit nothing here at all: the answer was real and off the bottom of the panel.
 */
/*
 * Where the panel reads from, settled once a frame before anything is drawn.
 *
 * TWO SEPARATE THINGS, and keeping them separate is the whole of it:
 *
 *   the WINDOW follows the hex scroll, always and exactly. Scrolling is a
 *   deliberate act and nothing may override it.
 *
 *   the HIGHLIGHT belongs to the BYTES, not to the window. It is drawn from
 *   sel_a/sel_b wherever those bytes happen to fall, so scrolling away hides it
 *   and scrolling back shows it again. Nothing clears it.
 *
 * On top of that, one event: a NEW selection made in the hex pane moves the
 * window once, so the reader sees what they just picked. After that the window
 * is the scroll's again.
 *
 * Two earlier rules each failed at one half. "The selection wins while it is on
 * the hex screen" kept the highlight and killed the scroll - the window stayed
 * pinned while the hex moved under it. "The selection wins if there is one" was
 * worse: a selection left over from an old drag pinned the window for good.
 * Neither separated the window from the highlight, which is what a selection in
 * any editor already does.
 */
/* How many bytes the hex pane is showing. The panel is a window inside this. */
uint64_t dis_hex_shown(const struct view *v)
{
	uint64_t per = (uint64_t)(v->per > 0 ? v->per : 16);

	return (uint64_t)(hex_last() - hex_top() + 1) * per;
}

/*
 * The furthest the panel may be scrolled inside the hex pane's range.
 *
 * THE PANEL IS A MAGNIFIER, NOT A SECOND VIEW OF THE FILE. The hex pane shows
 * about 270 bytes and the panel about 60, so the panel can only ever be looking
 * at part of what the hex shows - and the part is the reader's to choose. What
 * it must never do is show bytes the hex pane is not showing: two panes claiming
 * to be in step while looking at different places is worse than one pane.
 *
 * So the offset is bounded at both ends: zero is the top of the hex view, and
 * the maximum is as far down as it can go while its last row is still inside it.
 */
/*
 * THE SPAN THE CONTROL USES, AND WHY IT IS NOT THE MEASURED ONE.
 *
 * How many bytes the rows actually cover is known only after decoding them, and
 * it changes as the panel scrolls: seventeen instructions might be 52 bytes here
 * and 68 there. Feeding that into the scrollbar and into the clamp made both
 * unstable - the thumb grew and shrank while scrolling, the maximum offset moved
 * under the offset, and the offset was pushed back down by the clamp on the next
 * frame. That is what "the thumb stretches and the position slides back" is.
 *
 * A control has to be steady to be usable, so it is sized from the ROWS instead:
 * four bytes per row, which is close to the average x86 instruction and, more to
 * the point, never changes. The panel may reach a few bytes further or less than
 * the nominal; that is invisible, while a jumping scrollbar is not.
 *
 * The measured value is still kept - dis_span_bytes - and still used for the
 * bracket in the hex pane, which is a statement about what IS shown rather than
 * a control.
 */
uint64_t dis_span_of(const struct view *v)
{
	int rows = hex_bot() - dis_top() + 1;

	(void)v;
	return rows > 0 ? (uint64_t)rows * 4u : 64u;
}

static int dis_label(struct view *v, uint64_t foff, char *out, size_t cap);

/*
 * THE LATEST START THAT STILL FILLS THE PANEL, as a region offset.
 *
 * The clamp used to approximate this - stop `rows` bytes before the end, one
 * byte a row - and that reaches the last byte but overshoots when the
 * instructions are longer than a byte: `rows` instructions from `rgn_len - rows`
 * run past the end and the surplus rows come back blank. The exact answer needs
 * the instruction lengths, so it is decoded: the last `rows` instructions span
 * at most rows*DIS_MAX_INSN bytes, so decoding from there forward and keeping
 * the start of the one that leaves exactly `rows` behind is the start from which
 * the last row holds the last instruction and no row is blank.
 *
 * Bounded whatever the region size, because only that trailing window is walked.
 */

static uint64_t dis_last_start(struct view *v, uint64_t lo, uint64_t end,
			       unsigned rows)
{
	uint64_t back = (uint64_t)rows * DIS_MAX_INSN;
	uint64_t at = end > lo + back ? dis_sync(v, end - back) : lo;
	uint64_t ring[256];
	uint8_t cost[256];
	unsigned n = 0, cap = rows < 256u ? rows : 256u, k, sum = 0;

	if (!cap)
		return lo;
	if (at < lo)                    /* dis_sync can round to before lo */
		at = lo;
	/*
	 * A ROW IS NOT ALWAYS AN INSTRUCTION: a label takes a row of its own, so
	 * the last window holds fewer instructions where there are labels. The
	 * walk therefore keeps what each instruction COSTS in rows (one, and one
	 * more when a label is drawn above it) and the answer is the latest start
	 * from which the rows to the end still fill the panel.
	 */
	while (at < end) {
		char line[DIS_LINE_MAX], lab[8];
		uint64_t at0 = at;

		ring[n % cap] = at0;
		cost[n % cap] = dis_label(v, view_map(v, at0, 0), lab, sizeof lab) ? 2u : 1u;
		n++;
		if (!dis_format(v, &at, line, sizeof line, NULL, NULL, NULL,
				NULL, 0) || at <= at0)
			break;
	}
	/* Walk back from the end until the rows add up to a panelful. */
	for (k = 0; k < n && k < cap; k++) {
		sum += cost[(n - 1u - k) % cap];
		if (sum >= cap)
			return ring[(n - 1u - k) % cap];
	}
	return lo;      /* the whole window is less than a panelful: it all fits */
}

/* THE LATEST START THAT STILL FILLS THE PANEL over the whole region. */
static uint64_t dis_full_start(struct view *v, unsigned rows)
{
	return dis_last_start(v, 0, v->rgn_len, rows);
}

int64_t dis_max_bias(struct view *v)
{
	int nr = hex_bot() - dis_top() + 1;
	uint64_t shown, win, full;
	int64_t hi;

	if (nr < 1)
		nr = 1;

	/*
	 * A PINNED RANGE SCROLLS WITHIN ITSELF, to the EXACT last window.
	 *
	 * "View disassembly" on a hex selection pins the panel to that run, and
	 * the run can be far longer than the rows there are to show it - select
	 * a whole region and it is the whole region. The bound cannot be the hex
	 * pane's window, which a pinned panel does not follow; it is the start of
	 * the last window inside the pinned run, decoded rather than guessed the
	 * way dis_full_start does for the whole region. Guessing it as
	 * dis_len - span was the same span overshoot the region bound below used
	 * to have: for a run of one-byte instructions span is far more than the
	 * bytes a panelful shows, so the scroll stopped a span short and the tail
	 * of the run - the last instructions of win_x64_raw among them - could
	 * not be reached. Decoded, a run of one-byte instructions reaches its
	 * tail and a run of long ones leaves no blank row past the end.
	 */
	if (v->dis_len != KGENOME_BROKEN) {
		uint64_t end = v->dis_at + v->dis_len;

		if (end > v->rgn_len)
			end = v->rgn_len;
		full = dis_last_start(v, v->dis_at, end, (unsigned)nr);
		return full > v->dis_at ? (int64_t)(full - v->dis_at) : 0;
	}

	/*
	 * The panel inside the hex pane's window, bounded at ONE BYTE PER ROW -
	 * the least a row can show - not at span's nominal four. Span, being so
	 * much larger than the bytes one-byte shellcode actually shows, stopped
	 * the scroll a whole span short of where the region bound below wanted
	 * it, so the two disagreed and the smaller (this one) won and cut the
	 * tail off.
	 */
	shown = dis_hex_shown(v);
	win = (uint64_t)nr;
	hi = shown > win ? (int64_t)(shown - win) : 0;

	/*
	 * AND NOT PAST THE REGION'S LAST WINDOW, decoded exactly by
	 * dis_full_start so the final row holds the final instruction and no row
	 * comes back blank. Below rgn_at it means the whole region already fits
	 * from where the panel is; otherwise its offset from rgn_at is the most
	 * the panel may be scrolled.
	 */
	full = dis_full_start(v, (unsigned)nr);
	if (full <= v->rgn_at)
		hi = 0;
	else if (hi > (int64_t)(full - v->rgn_at))
		hi = (int64_t)(full - v->rgn_at);
	return hi;
}

void dis_follow_hex(struct view *v)
{
	int64_t at, hi;

	/*
	 * A pinned panel does not FOLLOW the hex pane, but its offset still has
	 * to be clamped - the rows it has change with the terminal's height, so
	 * a bias that was legal a frame ago need not be now. Only the second
	 * half below is skipped: where the window starts is dis_at, not the hex
	 * scroll. See dis_start.
	 */
	if (v->dis_len != KGENOME_BROKEN) {
		hi = dis_max_bias(v);
		if (v->dis_bias < 0)
			v->dis_bias = 0;
		if (v->dis_bias > hi)
			v->dis_bias = hi;
		return;
	}

	/* Kept inside the hex pane's range, every frame - the range changes with
	 * the terminal's height and with how much the last instruction covered,
	 * so a bias that was legal a frame ago need not be now. */
	hi = dis_max_bias(v);
	if (v->dis_bias < 0)
		v->dis_bias = 0;
	if (v->dis_bias > hi)
		v->dis_bias = hi;

	/*
	 * LOCKED TO THE SCROLL, OFFSET BY THE SELECTION.
	 *
	 * See dis_bias. The window is the scroll plus a constant, so a notch of
	 * scroll moves this panel by a notch - always, selection or not - and
	 * the constant is what keeps a selected run on these rows rather than
	 * sixty bytes above them.
	 */
	at = (int64_t)v->rgn_at + v->dis_bias;
	if (at < 0)
		at = 0;
	if ((uint64_t)at > v->rgn_len)
		at = (int64_t)v->rgn_len;
	v->dis_follow = (uint64_t)at;
}

/*
 * A new hex selection: set the bias so the run lands on these rows.
 *
 * Called where the selection is made rather than tested for every frame,
 * because it is an EVENT. Testing it per frame is what made the earlier
 * versions states rather than events, and a state cannot be told from a
 * leftover.
 */
void dis_bias_to_sel(struct view *v)
{
	uint64_t lo;

	if (!v->dis_open || v->dis_len != KGENOME_BROKEN)
		return;
	if (v->sel_a == KGENOME_BROKEN) {
		v->dis_bias = 0;                /* nothing picked: plain sync */
		return;
	}
	lo = v->sel_a < v->sel_b ? v->sel_a : v->sel_b;
	/* A little before it, so the run has something above it to be read
	 * against - an instruction on the first row with nothing before it
	 * reads as the start of something, and it usually is not. */
	if (lo > 16u)
		lo -= 16u;
	else
		lo = 0;
	v->dis_bias = (int64_t)lo - (int64_t)v->rgn_at;
	/*
	 * Clamped here as well as per frame, because a selection made near the
	 * bottom of the hex view would otherwise ask the panel to start past the
	 * end of it - and the reader would be looking at instructions the hex
	 * pane above is not showing.
	 */
	if (v->dis_bias < 0)
		v->dis_bias = 0;
	if (v->dis_bias > dis_max_bias(v))
		v->dis_bias = dis_max_bias(v);
}

static uint64_t dis_start(const struct view *v)
{
	/* Pinned: the run's start plus however far it has been scrolled. The
	 * bias is clamped to the run by dis_follow_hex, so this cannot leave
	 * it. */
	return v->dis_len != KGENOME_BROKEN
	       ? v->dis_at + (uint64_t)(v->dis_bias > 0 ? v->dis_bias : 0)
	       : v->dis_follow;
}

/*
 * Point the HEX selection at whatever the panel's line selection covers.
 *
 * One selection, seen two ways: the bytes light up in the hex pane, the
 * instructions light up here, and every menu item that already works on a byte
 * range works on this one. The alternative was a second selection with its own
 * copy of copy, declare and find hanging off it.
 */
/* The selection in reading order: (at0,c0) before (at1,c1). */
void dis_span(const struct view *v, uint64_t *at0, int *c0,
		     uint64_t *at1, int *c1)
{
	uint64_t aa = v->dis_a_at, ba = v->dis_b_at;
	int ac = v->dis_ac, bc = v->dis_bc;

	if (ba < aa || (ba == aa && bc < ac)) {
		uint64_t t = aa; aa = ba; ba = t;
		{ int u = ac; ac = bc; bc = u; }
	}
	*at0 = aa; *c0 = ac; *at1 = ba; *c1 = bc;
}

/*
 * Which columns of row `idx` are selected: [*from, *to), empty when none.
 *
 * The middle rows of a multi-row selection are taken whole, which is what a
 * text selection does everywhere - the first row from the anchor to its end,
 * the last from its start to the cursor.
 */
/*
 * MATCHED BY OVERLAP, NOT BY EQUALITY, because disassembly does not
 * self-synchronise.
 *
 * The selection remembers the offset an instruction STARTED at. Read the same
 * bytes from somewhere else - which is what scrolling does - and the boundaries
 * fall differently: the remembered offset can land in the middle of an
 * instruction, and then no row's start equals it and nothing is lit. That is the
 * highlight "disappearing on scroll", and it is not about the window at all.
 *
 * So a row is selected when its bytes OVERLAP the selected range. The columns
 * are still exact at the two ends: the row holding the first selected byte
 * starts at the anchor's column, the row holding the last ends at the cursor's,
 * and every row between is whole.
 */
/*
 * Does the HEX pane's selection cover the instruction at [at, at+alen)?
 *
 * One function because three places ask it and they must agree: the painter
 * marks the whole row on it, Copy takes the whole row on it, and the panel's
 * right-click leaves the selection alone on it. They were not one function, and
 * the copy simply did not know about this kind of selection - so a range picked
 * in the hex pane lit up here and then copied nothing.
 */
/* Is there a selection at all, and was it made in the hex pane? */
int dis_hex_sel(const struct view *v)
{
	return v->sel_a != KGENOME_BROKEN && !v->sel_from_dis;
}

static int dis_hex_marks(const struct view *v, uint64_t at, uint64_t alen)
{
	uint64_t lo, hi;

	if (!dis_hex_sel(v))
		return 0;
	lo = v->sel_a < v->sel_b ? v->sel_a : v->sel_b;
	hi = v->sel_a < v->sel_b ? v->sel_b : v->sel_a;
	return at + alen > lo && at <= hi;
}

int dis_cols(const struct view *v, uint64_t at, uint64_t alen, int len,
		    int *from, int *to)
{
	uint64_t a0, a1;
	int c0, c1;

	*from = *to = 0;
	if (!v->dis_have || !alen)
		return 0;
	dis_span(v, &a0, &c0, &a1, &c1);
	if (at + alen <= a0 || at > a1)
		return 0;               /* no bytes in common */
	*from = (at <= a0 && a0 < at + alen) ? c0 : 0;
	*to   = (at <= a1 && a1 < at + alen) ? c1 + 1 : len;
	if (*from > len)
		*from = len;
	if (*to > len)
		*to = len;
	return *to > *from;
}

void dis_sync_bytes(struct view *v)
{
	uint64_t a, b;
	int c0, c1, k;

	if (!v->dis_have || v->dis_lines <= 0)
		return;
	dis_span(v, &a, &c0, &b, &c1);
	/*
	 * The bytes of the instructions the selection TOUCHES, whole.
	 *
	 * A character selection can stop halfway through a mnemonic, and half a
	 * mnemonic has no bytes. What the byte range is for is Copy hex and
	 * Declare as hex, and both of those want instructions - so the range is
	 * rounded out to the ones the text sits in.
	 */
	v->sel_a = a;
	v->sel_b = b;
	/* To the END of the instruction the selection stops in: what the byte
	 * range is for is Copy hex and Declare as hex, and both want whole
	 * instructions. */
	for (k = 0; k < v->dis_lines; k++)
		if (v->dis_line_at[k] == b && !v->dis_line_lbl[k]) {
			v->sel_b = b + v->dis_line_len[k] - 1u;
			break;
		}
	v->sel_from_dis = 1;
}

/*
 * THE FIRST INSTRUCTION BOUNDARY AT OR AFTER `want`.
 *
 * x86 IS NOT SELF-DELIMITING, and the panel's start moves in bytes: the scroll
 * offset is a byte count and the hex pane's rows are sixteen bytes, so where the
 * panel begins is almost never where an instruction begins. Decoding from there
 * reads the middle of one instruction as the start of another and produces a
 * listing that does not exist - measured on x86_clear, scrolling turned
 *
 *     00000057  31 db     XOR ebx, ebx        (real, and ndisasm agrees)
 *
 * into
 *
 *     00000058  db f7     FCOMI st0, st7      (not in the file at all)
 *
 * and further down produced a six-byte AND that swallowed the `MOV ecx, esp` at
 * 0x72 - a real instruction that then had no row of its own.
 *
 * So the start is re-synchronised: decode forward from a little way back and
 * take the first boundary that reaches `want`. This is what a disassembler does
 * and it is why the answer is stable - the stream converges on the true
 * boundaries within a few instructions whatever it is entered at.
 */
/*
 * THE ANNOTATIONS: a function's name where it starts, a label where a jump
 * lands, the callee's name at a call, the syscall's name at a syscall.
 *
 * Trailing text on the row, not extra rows: a click, a selection and the copy
 * all map a screen row to one instruction through dis_line_at, and a row that
 * stood for no instruction would break every one of those.
 *
 * Everything is in FILE OFFSETS, the space the panel's address column and the
 * formatter's resolved branch targets are already in, and the function table
 * (mtn_funcs, the one the segmenter uses, sorted by offset) is in the same
 * space. A name is read from the symbol block through the function's value and
 * section, as kv_mutation does, so there is no second symbol lookup.
 */
static void dis_func_name(struct view *v, const struct kgenome_func *f,
			  char *out, size_t cap);

static const struct kgenome_func *dis_func_at(struct view *v, uint64_t off,
					      int *start)
{
	char nm[8];
	const struct kgenome_func_set *fs = mtn_funcs(v, cur_obj(v));
	uint32_t lo = 0, hi = fs->n;

	/* The last function whose start is <= off. */
	while (lo < hi) {
		uint32_t mid = lo + (hi - lo) / 2u;

		if (fs->v[mid].off <= off)
			lo = mid + 1u;
		else
			hi = mid;
	}
	if (!lo)
		return NULL;
	if (off >= fs->v[lo - 1u].off + fs->v[lo - 1u].len)
		return NULL;
	/* A section symbol is a symbol with no name and not a function. */
	dis_func_name(v, &fs->v[lo - 1u], nm, sizeof nm);
	if (!nm[0])
		return NULL;    /* a section symbol is not a function */
	*start = fs->v[lo - 1u].off == off;
	return &fs->v[lo - 1u];
}

/* The function's name as the symbol block records it; empty when it has none. The panel
 * invents no name for a function without a symbol. */
static void dis_func_name(struct view *v, const struct kgenome_func *f,
			  char *out, size_t cap)
{
	const struct object *o = cur_obj(v);

	kof_sym_name_at(o->sym, o->sym_n, f->value, (int)f->shndx, out, cap);
}

/*
 * The NAME of the function a call or jump goes to, as a comment beside the
 * address, when the engine's tables say that address is the start of a named
 * function. It adds what is already known and works nothing out: a jump into
 * the middle of a function gets no comment, so a jump target is never written
 * as if it were a function.
 */
static int dis_target_name(struct view *v, const struct kgenome_x86_insn *ix,
			   uint64_t foff, char *out, size_t cap)
{
	unsigned cat = kgenome_x86_cat(ix);
	const struct kgenome_func *t;
	struct kgenome_x86_op op;
	int start = 0;

	if (cat != KGENOME_X86_C_CALL && cat != KGENOME_X86_C_UNCOND_BR)
		return 0;
	if (!kgenome_x86_nops(ix))
		return 0;
	kgenome_x86_operand(ix, 0, &op);
	if (op.type != KGENOME_X86_OP_REL)
		return 0;
	t = dis_func_at(v, foff + ix->len + (uint64_t)op.v, &start);
	if (!t || !start)
		return 0;
	dis_func_name(v, t, out, cap);
	return out[0] != 0;
}

/*
 * The label that goes on a row of its own above the instruction at `foff`: the
 * name of the function that starts there, as the engine's function table and
 * symbol block give it. Nothing else is worked out here - no jump targets, no
 * syscall numbers, no callee names: those are analysis, and the panel shows what
 * the engine reported and computes none of it. 0 when no function starts here.
 */
static int dis_label(struct view *v, uint64_t foff, char *out, size_t cap)
{
	const struct kgenome_func *f;
	const struct object *o = cur_obj(v);
	char name[64];
	int start = 0;

	/* ANALYSED: the labels are the engine's (kof_codenotes), a function's and a jump's, and kind says which. */
	if (o->notes_done) {
		uint32_t cnt, i;
		const struct kof_note *nt = kof_codenotes_at(&o->notes, foff, &cnt);

		for (i = 0; i < cnt; i++)
			if (nt[i].kind == KOF_NOTE_FUNC || nt[i].kind == KOF_NOTE_LABEL) {
				snprintf(out, cap, "%s", kof_codenotes_text(&o->notes, &nt[i]));
				return nt[i].kind == KOF_NOTE_FUNC ? 1 : 2;
			}
		return 0;
	}
	f = dis_func_at(v, foff, &start);
	if (!f || !start)
		return 0;
	dis_func_name(v, f, name, sizeof name);
	snprintf(out, cap, "%s:", name);
	return 1;
}

/* Append `sep` and `what` to a row's text - whole, or not at all when it does not fit: a comment is never cut in the middle of a word. */
static void dis_say(char *text, size_t cap, const char *sep, const char *what)
{
	size_t have = strlen(text), n = strlen(sep) + strlen(what);

	if (have + n + 1u <= cap)
		snprintf(text + have, cap - have, "%s%s", sep, what);
}

/*
 * THE FLAGS, KEPT AS ROWS ARE DRAWN IN ORDER, AND WHAT EACH ROW SAYS OF THEM. A CMP or TEST row says the COMPARISON it makes (`compare rax with 0`); a conditional
 * jump row says the CONDITION it jumps on (`jump if rax >= 0`), read from the comparison above it - stepping over instructions that leave the flags alone
 * (kgenome_x86_keeps_flags) and forgetting them at any other, and at a row that is not the next of the last. A jump drawn with no comparison known (the
 * panel starts at it) says the flag it tests. The words are the lib's (kgenome_x86_cmp_text, kgenome_x86_cond_text); this keeps the one instruction between
 * rows, which is all that is not the lib's.
 */
static void dis_cond_note(struct view *v, const struct kgenome_x86_insn *ix, uint64_t at, uint64_t foff,
			  char *text, size_t cap)
{
	char cd[160], cm[2 * KGENOME_X86_TEXT];
	const char *sep;

	if (v->dis_next != at)
		v->dis_fl_ok = 0;
	sep = strstr(text, "  ; ") ? ", " : "  ; ";
	if (ix->id == KGENOME_X86_I_CMP || ix->id == KGENOME_X86_I_TEST) {
		if (kgenome_x86_cmp_text(ix, foff, cm, sizeof cm))
			dis_say(text, cap, sep, cm);
		v->dis_fl = *ix;
		v->dis_fl_rip = foff;
		v->dis_fl_ok = 1;
	} else if (ix->id == KGENOME_X86_I_Jcc) {
		if (kgenome_x86_cond_text(ix, v->dis_fl_ok ? &v->dis_fl : NULL, v->dis_fl_rip, cd, sizeof cd)) {
			snprintf(cm, sizeof cm, "jump if %s", cd);
			dis_say(text, cap, sep, cm);
		}
	} else if (!kgenome_x86_keeps_flags(ix)) {
		v->dis_fl_ok = 0;
	}
	v->dis_next = at + ix->len;
}

/*
 * ONE INSTRUCTION, AS A PLAIN LINE: "<offset>  <bytes>  <mnemonic>".
 *
 * The exact text the panel shows and the clipboard gets, from ONE place, so the
 * two cannot drift - the draw builds its rows through this and so does Copy, and
 * "the same string on screen and in the clipboard" is a property of there being
 * one function rather than a promise two blocks of code keep.
 *
 * It advances *at by the instruction's length and returns that length, so a
 * caller walking a range needs nothing else. Data that will not decode is one
 * byte named "(data)".
 *
 * The out-parameters are for the DRAW, which re-emits the line coloured and so
 * needs the pieces: the raw bytes, how many of them the row shows, whether the
 * mnemonic decoded, and the mnemonic on its own. Copy passes NULL for all of
 * them - it wants the flat line and nothing else.
 */
unsigned dis_format(struct view *v, uint64_t *at, char *line, size_t cap,
			   uint8_t *bytes_out, unsigned *ix_len_out,
			   int *ok_out, char *text_out, size_t text_cap)
{
	uint8_t buf[DIS_MAX_INSN];
	struct kgenome_x86_insn ix;
	char text[DIS_TEXT_MAX];
	unsigned got, j, w;

	if (ix_len_out)
		*ix_len_out = 1;
	if (ok_out)
		*ok_out = 0;
	got = dis_gather(v, *at, buf, DIS_MAX_INSN);
	if (!got)
		return 0;
	if (bytes_out)
		memcpy(bytes_out, buf, DIS_MAX_INSN);
	w = (unsigned)snprintf(line, cap, "%08llx  ",
			       (unsigned long long)view_map(v, *at, 0));
	if (kgenome_x86_decode(&ix, buf, got, v->dis_bits == 32 ? 32 : 64) != KGENOME_OK) {
		snprintf(line + w, cap - w, "%02x%*s (data)", buf[0], 19, "");
		v->dis_fl_ok = 0;       /* bytes that are not an instruction say nothing of the flags */
		(*at)++;
		return 1;
	}
	if (ix_len_out)
		*ix_len_out = ix.len < 7u ? ix.len : 7u;
	if (ok_out)
		*ok_out = 1;
	for (j = 0; j < ix.len && j < 7u && w + 3 < cap; j++)
		w += (unsigned)snprintf(line + w, cap - w, "%02x ", buf[j]);
	for (; j < 7u && w + 3 < cap; j++)
		w += (unsigned)snprintf(line + w, cap - w, "   ");
	if (!kgenome_x86_format(&ix, view_map(v, *at, 0), text, sizeof text))
		text[0] = 0;
	kgenome_x86_shorten(text);
	{
		char nm[64];
		const struct object *o = cur_obj(v);

		/* The operand keeps its address; what the engine says about the instruction is a comment. */
		if (o->notes_done) {
			uint32_t cnt, i;
			const struct kof_note *nt = kof_codenotes_at(&o->notes, view_map(v, *at, 0), &cnt);

			for (i = 0; i < cnt; i++)
				if (nt[i].kind == KOF_NOTE_COMMENT)
					snprintf(text + strlen(text), sizeof text - strlen(text), "  ; %s",
						 kof_codenotes_text(&o->notes, &nt[i]));
		} else if (dis_target_name(v, &ix, view_map(v, *at, 0), nm, sizeof nm)) {
			snprintf(text + strlen(text), sizeof text - strlen(text), "  ; %s", nm);
		}
	}
	dis_cond_note(v, &ix, *at, view_map(v, *at, 0), text, sizeof text);
	snprintf(line + w, cap - w, "%s", text);
	if (text_out)
		snprintf(text_out, text_cap, "%s", text);
	*at += ix.len;
	return ix.len;
}

uint64_t dis_sync(struct view *v, uint64_t want)
{
	uint64_t at;
	unsigned guard;

	if (!want)
		return 0;
	at = want > DIS_RESYNC ? want - DIS_RESYNC : 0;

	for (guard = 0; at < want && guard < DIS_RESYNC; guard++) {
		uint8_t buf[DIS_MAX_INSN];
		struct kgenome_x86_insn ix;
		unsigned got = dis_gather(v, at, buf, DIS_MAX_INSN);

		if (!got)
			return want;            /* nothing to read: leave it */
		if (kgenome_x86_decode(&ix, buf, got, v->dis_bits == 32 ? 32 : 64) == KGENOME_OK &&
		    ix.len)
			at += ix.len;
		else
			at += 1u;               /* data: one byte, as the panel does */
	}
	/* At or past `want` - never before it, so the panel does not silently
	 * show bytes the scroll had already left behind. */
	return at;
}

/*
 * The row a click or a drag on row `idx` means: itself, or - when it is a label
 * and has no bytes - the instruction row below it, else the one above. -1 when
 * the panel has no instruction row at all.
 */
int dis_real_row(const struct view *v, int idx)
{
	int k;

	if (idx < 0 || idx >= v->dis_lines || !v->dis_line_lbl[idx])
		return idx;
	for (k = idx + 1; k < v->dis_lines; k++)
		if (!v->dis_line_lbl[k])
			return k;
	for (k = idx - 1; k >= 0; k--)
		if (!v->dis_line_lbl[k])
			return k;
	return -1;
}

void draw_disasm(struct out *o, struct view *v)
{
	int head = dis_top() - 1;
	int row;
	int col = TREE_W + 3;
	uint64_t at = dis_sync(v, dis_start(v));
	uint64_t end = v->dis_len == KGENOME_BROKEN ? v->rgn_len
					        : v->dis_at + v->dis_len;
	char note[32], label[256];
	int lkind;
	uint64_t labeled = KGENOME_BROKEN;      /* the address whose label is already drawn */

	if (!g_disasm_rows)
		return;
	if (end > v->rgn_len)
		end = v->rgn_len;

	/*
	 * The heading, with the two controls a reader needs and nothing else:
	 * which mode the bytes are being read in, and a way to close.
	 */
	out_at(o, head, col);
	/*
	 * "x86" and "x64", not "x32" and "x64".
	 *
	 * The width in bits is what the field holds and printing it directly was
	 * the obvious thing, but nobody calls 32-bit Intel "x32" - the engine
	 * itself writes ELF-x86 in every finding, and a panel using a second name
	 * for the same architecture is a name a reader has to translate. x32 is
	 * also a real and different thing (the ILP32 ABI on amd64), so it is not
	 * merely unconventional here, it is taken.
	 */
	snprintf(note, sizeof note, " Disassembly  [%s]%s ",
		 v->dis_bits == 32 ? "x86" : "x64", cur_obj(v)->notes_done ? " analysed" : "");
	/* The panel's own palette here too, so nothing in this strip is yellow -
	 * the hex pane above is largely yellow already. */
	out_fmt(o, A_DIM "--" A_OFF A_D_MNEM "%s" A_OFF, note);
	if (v->dis_len != KGENOME_BROKEN)
		out_fmt(o, A_DIM " selection %llu B " A_OFF,
			(unsigned long long)v->dis_len);
	out_str(o, A_DIM);
	{
		int used = col + 2 + (int)strlen(note) +
			   (v->dis_len != KGENOME_BROKEN ? 20 : 0);
		int k;

		for (k = used; k < g_cols - 4; k++)
			out_str(o, "-");
	}
	out_str(o, A_OFF);
	out_at(o, head, g_cols - 3);
	out_str(o, A_D_KEY "[x]" A_OFF);

	v->dis_lines = 0;
	for (row = dis_top(); row <= hex_bot(); row++) {
		uint8_t buf[DIS_MAX_INSN];
		char text[DIS_TEXT_MAX];
		char line[DIS_LINE_MAX];
		uint64_t at0 = at;              /* before the length is added */
		int from, to, len;
		unsigned ix_len = 1;            /* bytes this row stands for */
		int ok_decode = 0;

		out_at(o, row, col);
		if (at >= end) {
			out_str(o, "\033[K");
			continue;
		}
		/*
		 * A LABEL IS A ROW OF ITS OWN, as a disassembler draws it: it takes a
		 * screen row and stands for no instruction, so the instruction under
		 * it is drawn on the next row (`labeled` stops it being drawn twice).
		 * It is recorded like any row so that screen row n is still entry n;
		 * dis_line_lbl marks it so a click or a drag lands on the instruction
		 * below instead - there are no bytes in a label to select.
		 */
		if (at != labeled &&
		    (lkind = dis_label(v, view_map(v, at, 0), label, sizeof label))) {
			if (v->dis_lines < (int)(sizeof v->dis_line /
						 sizeof v->dis_line[0])) {
				v->dis_line_at[v->dis_lines]  = at;
				v->dis_line_len[v->dis_lines] = 0;
				v->dis_line_lbl[v->dis_lines] = 1;
				snprintf(v->dis_line[v->dis_lines++],
					 sizeof v->dis_line[0], "%.318s", label);
			}
			{
				/* the name in its colour (a function and a jump label are told apart by it), the xrefs after it dim */
				const char *xr = strstr(label, "  ; ");
				size_t nl = xr ? (size_t)(xr - label) : strlen(label);

				out_str(o, lkind == 1 ? A_D_KEY : A_D_IMM);
				out_add(o, label, nl);
				out_str(o, A_OFF);
				if (xr) {
					out_str(o, A_DIM);
					out_str(o, xr);
					out_str(o, A_OFF);
				}
				out_str(o, "\033[K");
			}
			labeled = at;
			continue;
		}
		/*
		 * Built by dis_format, coloured below. There is one formatter so
		 * the clipboard cannot get a line the screen never showed - see
		 * dis_format and dis_copy.
		 */
		if (!dis_format(v, &at, line, sizeof line, buf, &ix_len,
				&ok_decode, text, sizeof text)) {
			out_str(o, "\033[K");
			continue;
		}
		if (v->dis_lines < (int)(sizeof v->dis_line /
					 sizeof v->dis_line[0])) {
			v->dis_line_at[v->dis_lines]  = at0;
			v->dis_line_len[v->dis_lines] = at - at0;
			v->dis_line_lbl[v->dis_lines] = 0;
			snprintf(v->dis_line[v->dis_lines++],
				 sizeof v->dis_line[0], "%s", line);
		}
		/*
		 * Three things can mark a row, drawn in this order.
		 *
		 * The TEXT SELECTION is characters and is drawn as a span, so it
		 * has to be written in three pieces. The HEX selection marks
		 * whole instructions and in two colours, which is the one thing
		 * the hex pane above cannot show: a marker is a run of bytes,
		 * and a run that starts or ends in the MIDDLE of an instruction
		 * is fragile - the same source rebuilt with another register
		 * allocation moves those bytes and the signature quietly stops
		 * matching. Wholly covered is one colour, cut is another.
		 */
		/*
		 * ONE MARK, AND IT IS THE READER'S OWN SELECTION.
		 *
		 * A second marking - the instructions a HEX selection covered,
		 * in two colours for whole and cut - was built and taken back
		 * out. It repeated what the hex pane already shows one row up,
		 * it needed a colour that clashed with none of three others, and
		 * keeping it visible meant holding this panel still while the
		 * hex scrolled under it. Three costs for a fact the reader could
		 * already see. What is marked here is what was dragged out here.
		 */
		len = (int)strlen(line);
		/*
		 * TWO WAYS TO DRAW A ROW, and which one is used depends on
		 * whether the reader has a TEXT selection over it.
		 *
		 * A text selection is characters: it can start mid-mnemonic, so
		 * it is drawn as three flat runs with a background on the
		 * middle one, and the syntax colours give way. Anything else
		 * gets painted properly - offset, bytes, mnemonic, operands -
		 * with the bytes a HEX selection covers lit one at a time.
		 *
		 * Giving way rather than combining: a background plus six
		 * foregrounds is a row nobody can read, and while a reader is
		 * dragging text out, what they want to see is the extent of
		 * what they have got.
		 */
		if (dis_cols(v, at0, at - at0, len, &from, &to)) {
			out_add(o, line, (size_t)from);
			out_str(o, A_SELB);
			out_add(o, line + from, (size_t)(to - from));
			out_str(o, A_OFF);
			out_str(o, line + to);
			out_str(o, "\033[K");
		} else {
			/*
			 * THE WHOLE LINE, when the hex selection touches this
			 * instruction.
			 *
			 * Marking only the covered BYTES was tried and is too
			 * quiet: the bytes are two hex digits in the middle of
			 * a row and the eye does not find them, which is the
			 * opposite of what a highlight is for. An instruction
			 * either is part of what the reader picked or it is
			 * not, and the row is the unit that says so.
			 */
			int marked = dis_hex_marks(v, at0, at - at0);
			unsigned k;
			if (marked) {
				out_str(o, A_D_SEL);
				out_fmt(o, "%s" A_OFF "\033[K", line);
			} else {
				out_str(o, A_D_OFF);
				out_add(o, line, 8);
				out_str(o, A_OFF "  ");
				for (k = 0; k < 7u; k++) {
					if (k < ix_len) {
						out_str(o, A_D_BYTE);
						out_fmt(o, "%02x", buf[k]);
						out_str(o, A_OFF " ");
					} else {
						out_str(o, "   ");
					}
				}
				if (ok_decode)
					dis_paint(o, text);
				else
					out_str(o, A_DIM "(data)" A_OFF);
				out_str(o, "\033[K");
			}
		}
	}
	/*
	 * THE PANEL'S OWN SCROLLBAR, and what it is a bar OVER.
	 *
	 * Not the file: the hex pane's range. The panel is a window inside what
	 * the hex is showing - about sixty bytes of about two hundred and
	 * seventy - and until this bar was here that was invisible: a reader who
	 * selected bytes low in the hex pane saw nothing light up and had no way
	 * to know the panel simply did not reach that far. The bar says how much
	 * of the hex view is being disassembled and where in it the rows are, and
	 * it can be dragged.
	 *
	 * Drawn only when there is somewhere to scroll to. A full-length thumb
	 * on a panel that already covers everything is a control that does
	 * nothing.
	 */
	/*
	 * THE PANEL'S SCROLLBAR.
	 *
	 * A bar over the hex pane's range rather than over the file: the panel
	 * is a window inside what the hex is showing - about sixty bytes of
	 * nearly three hundred - and without this bar that was invisible, so a
	 * reader who selected bytes low in the hex pane saw nothing light up and
	 * had no way to know the panel did not reach that far.
	 *
	 * The TOTAL is the range the offset can actually take, not the hex
	 * pane's whole span. Those differ near the end of a region, where the
	 * hex pane draws rows past the last byte: measured against the hex span
	 * the thumb stopped short of the bottom with the panel already as far
	 * down as it goes, which reads as a bar that can still be dragged.
	 *
	 * Drawn through the shared scrollbar, so this bar looks like every
	 * other one - see the note there.
	 */
	if (dis_max_bias(v) > 0)
		kv_scrollbar(o, g_cols, dis_top(), hex_bot(),
			  (uint64_t)v->dis_bias,
			  (uint64_t)dis_max_bias(v) + dis_span_of(v),
			  dis_span_of(v));
}

/*
 * Open, close, and how many rows it takes.
 *
 * Half of what the hex column has, so both halves stay usable - a panel that
 * took most of the screen would answer the question by hiding the evidence -
 * and never fewer than DIS_MIN_ROWS, because a panel too short to hold an
 * instruction is not a panel.
 */
void dis_toggle(struct view *v, uint64_t at, uint64_t len)
{
	if (v->dis_open && len == KGENOME_BROKEN) {
		v->dis_open = 0;
		g_disasm_rows = 0;
		v->dis_have = 0;
		return;
	}
	if (!v->dis_open) {
		v->dis_bits = dis_default_bits(v);
		/*
		 * Nothing selected, spelled out. The struct is cleared to zero
		 * on a file switch and zero is a valid ROW, so a panel opened
		 * after one would come up with its first line already lit.
		 */
		v->dis_have = 0;
		v->dis_dragging = 0;
	}
	/*
	 * Opened from the menu with nothing selected, it moves to CODE.
	 *
	 * Headers, data and the unclaimed tail all decode into something -
	 * every byte does - and none of it means anything. A reader who opens a
	 * disassembly wants the code, so the panel goes and gets it rather than
	 * showing whichever region the tree happened to be on. Moving the TREE
	 * rather than pointing the panel somewhere else keeps the two in step:
	 * the hex shows the same bytes, which is the whole reason the panel is
	 * under it.
	 *
	 * Only on the way open, and only when nothing was selected: a reader who
	 * picked a range meant that range, and one who is already reading a
	 * region did not ask to be moved.
	 */
	if (!v->dis_open && len == KGENOME_BROKEN) {
		uint32_t k;

		for (k = 0; k < v->n_node; k++)
			if (v->node[k].obj == v->node[v->sel_node].obj &&
			    v->node[k].mask &&
			    !strcmp(v->node[k].label, "CODE")) {
				goto_node(v, k);
				break;
			}
	}
	v->dis_open = 1;
	v->dis_at = at;
	v->dis_len = len;
	/* Somewhere sane for the first frame; dis_follow_hex settles it from
	 * there. */
	v->dis_follow = len == KGENOME_BROKEN ? v->rgn_at : at;
	v->dis_bias = 0;
	dis_bias_to_sel(v);
}

/*
 * Analysis > Analyze disassembly: the engine reads the WHOLE object's code once (branches, calls, syscalls, who refers to what) and names what it
 * found; the panel then shows the part it is looking at. Nothing is worked out here - this asks, keeps the answer on the object and says how it went.
 * Run again it replaces the answer, which is the only way to see a change in what the engine knows.
 */
void dis_analyse(struct view *v)
{
	struct object *o = cur_obj(v);
	int ok;

	kof_codenotes_free(&o->notes);
	o->notes_done = 0;
	ok = kof_codenotes_build(&o->ctx, o->buf, mtn_funcs(v, o), o->sym, o->sym_n,
				 v->dis_bits ? (unsigned)v->dis_bits : (unsigned)dis_default_bits(v), &o->notes);
	if (ok) {
		o->notes_done = 1;
		snprintf(v->act_msg, sizeof v->act_msg, "Analysed the whole object: %u note(s)", o->notes.n);
	} else {
		snprintf(v->act_msg, sizeof v->act_msg, o->notes.status == KGENOME_NOMEM
			 ? "Analysis stopped: out of memory" : "Nothing to analyse: no decoder for this object's code");
	}
	v->act_ok = ok;
}

/* The analysis of the current object no longer holds (the width it was read in changed): drop it, so the panel shows only what is true now. */
void dis_drop_analysis(struct view *v)
{
	struct object *o = cur_obj(v);

	kof_codenotes_free(&o->notes);
	o->notes_done = 0;
}
