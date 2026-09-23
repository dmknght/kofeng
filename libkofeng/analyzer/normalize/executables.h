/*
 * executables.h - the same PE or ELF, said more plainly.
 *
 * WHAT THIS IS FOR, AND IT IS NOT A SPEED FEATURE.
 *
 * Some of what a binary carries is written in a form the matcher cannot read.
 * A UTF-16 marker is the same letters with a zero between each one, so an
 * ASCII pattern does not match it. A base64 payload is not its own bytes at
 * all. In both cases the engine can SEE the bytes and still not see the thing.
 *
 * The obvious fix is to teach the matcher: a second gram probe for the widened
 * form, a stride selector at each candidate, a match extent that says which
 * stride hit. That is three changes to the hottest path in the engine, each one
 * a chance to lose a match quietly. This is the other fix: say the object once,
 * plainly, and let the matcher stay exactly as it is.
 *
 *
 * WHAT IT SAVES IN BYTES, MEASURED, SO NOBODY READS THIS AS AN OPTIMISATION.
 *
 *     293 ELF64 from /usr/bin, 153.6 MB    null runs 2.6%   wide 0.0%
 *     1129 PE, 4043.9 MB                   null runs 0.9%   wide 0.2%
 *
 * One to three percent. That is not a reason to build anything. What makes it
 * worth building is the two lines above the numbers: the wide marker becomes
 * matchable and the encoded payload becomes scannable, and neither costs a line
 * of change in kofmatch.c.
 *
 * The distribution is worth knowing anyway, because the average hides it: the
 * saving is concentrated in SMALL files. comcat.dll is 73% zero padding,
 * msimsg.dll 68%, and a dozen more stub DLLs sit beside them - while one large
 * binary saves nothing and dominates the byte total. A sweep of a machine meets
 * many small files; a scan of one big file meets none of this.
 *
 *
 * NEVER LONGER THAN THE INPUT.
 *
 * Every operation here removes bytes - a zero run becomes two zeros, a wide run
 * becomes half of itself - so the output is bounded by the input and there is
 * no bomb to cap. script_executables.h states the same invariant for scripts and for
 * the same reason; this is the binary half of that idea.
 *
 *
 * THE SAFETY PROPERTY, AND IT IS THE WHOLE OF WHY TWO ZEROS AND NOT ONE.
 *
 * A literal pattern CANNOT CONTAIN A ZERO BYTE. ksigbuilder accepts six escapes
 * in a literal - \\ \" \? \t \n \r - and refuses \x with "use a hex pattern for
 * anything else", so there is no way to write one. That is not an accident this
 * relies on quietly; it is checked by a test beside this file.
 *
 * From it:
 *
 *   A zero-free pattern matches a run of consecutive NON-ZERO bytes. Collapsing
 *   a zero run to TWO zeros never puts two non-zero bytes side by side that were
 *   not side by side before, and never shortens a non-zero run. So no zero-free
 *   match is created and none is lost.
 *
 * Collapse to ONE zero and that breaks twice over: "41 00 00 42" would become
 * "41 00 42", which is a match for a wide pattern that was not there - and the
 * single zero reads as the high half of a UTF-16 character that does not exist.
 *
 * De-widening is the one operation that DELIBERATELY creates matches: "41 00 42
 * 00" becomes "41 42", and a pattern for "AB" now matches where it could not
 * before. That is the point of it. What it must never do is LOSE one, and it
 * does not: every non-zero byte of the run survives, in order.
 *
 *
 * WHAT IT MUST NOT BE RUN OVER.
 *
 * Code and symbol regions. Code because an instruction stream has no text to
 * normalise and every byte of it is an operand somebody might match; symbols
 * because a table is a structure, not prose, and collapsing inside one moves
 * every entry after it. The caller chooses the spans; this file does not parse
 * and does not guess.
 *
 *
 * OFFSETS BELONG TO THE INPUT, ALWAYS.
 *
 * The output is a DERIVED OBJECT with its own offset space, never a rewrite of
 * the original. Nothing that reads or writes the file at a position may be
 * handed an offset from here: kof_unpack_peek, kof_find_str_at and above all
 * cure_patch address the object as it lies on disk, and a module author has no
 * way to know which view an offset came from. The span map below is what maps
 * an output position back when a report needs to name one.
 */

#ifndef KOFENG_NORMALIZE_EXECUTABLES_H
#define KOFENG_NORMALIZE_EXECUTABLES_H

#include <stddef.h>
#include <stdint.h>

/*
 * THE TWO OPERATIONS, ASKED FOR SEPARATELY.
 *
 * A caller may want the wide half without the zero half: de-widening changes
 * what MATCHES and collapsing only changes how much is swept, so they answer to
 * different reasons and a caller that wants one should not pay for the other.
 */
#define KOF_EXE_NORM_NULLRUN (1u << 0)   /* long zero runs -> two zeros */
#define KOF_EXE_NORM_UNWIDE  (1u << 1)   /* UTF-16LE ASCII runs -> ASCII */

/*
 * THE FLOORS, AND BOTH ARE THE NUMBERS THE MEASUREMENT ABOVE WAS TAKEN WITH.
 *
 * A zero run shorter than this is left alone: collapsing it saves fewer bytes
 * than the span it costs to record, and a map entry is the expensive half.
 *
 * A wide run shorter than this is not believed. Two bytes of "printable, zero"
 * happen constantly in ordinary data - a small integer beside a letter - and
 * treating them as text would rewrite structure as prose.
 */
#define KOF_EXE_NORM_NULL_MIN 8u         /* zero bytes */
#define KOF_EXE_NORM_WIDE_MIN 8u         /* characters, so sixteen bytes */

/*
 * WHERE A PIECE OF THE OUTPUT CAME FROM.
 *
 * One span per contiguous stretch, in output order, covering the output
 * exactly: spans are adjacent and there are no holes, so a binary search on
 * dst_off answers "which span holds this output offset" and the kind says how
 * to turn it into an input offset.
 */
enum kof_exe_norm_kind {
	/* src_len == dst_len, byte for byte. in[src_off + k] is out[dst_off + k]. */
	KOF_EXE_NORM_COPY = 0,
	/* src_len == 2 * dst_len. in[src_off + 2k] is out[dst_off + k]; the odd
	 * bytes were the zero high halves and are gone. */
	KOF_EXE_NORM_UNWIDENED,
	/* dst_len == 2, src_len >= KOF_EXE_NORM_NULL_MIN. Every byte on both sides
	 * is zero, so any output offset inside maps to src_off honestly - there
	 * is no better answer and no worse one. */
	KOF_EXE_NORM_NULLS
};

struct kof_exe_norm_span {
	uint64_t src_off;
	uint64_t src_len;
	uint64_t dst_off;
	uint64_t dst_len;
	uint8_t  kind;      /* enum kof_exe_norm_kind */
};

/*
 * NORMALISE [in, in + n) INTO out.
 *
 * `ops` is the union of KOF_EXE_NORM_* the caller wants. `cap` bounds the output
 * and n is always enough, because the output is never longer than the input.
 *
 * `spans` may be NULL when the caller only means to scan and will never report
 * a position. When it is not NULL, `span_cap` bounds it and `n_spans` gets the
 * count written.
 *
 * RETURNS THE OUTPUT LENGTH, OR 0. Zero means one of three things and the
 * caller treats them alike: nothing was there to normalise, the output would
 * not fit, or the spans would not fit. All three say "scan the original and do
 * not make a child", which is the right answer to every one of them.
 *
 * ZERO WHEN NOTHING CHANGED IS THE COMMON CASE and it is cheap on purpose: the
 * measurement says one to three percent of bytes move, so most objects come
 * back unchanged and must not have paid for a copy to find out.
 */
/*
 * THE SAME BYTES, THE SAME LENGTH, THE WIDE TEXT READ AS TEXT.
 *
 * Writes exactly `n` bytes. Every offset in the output is the same offset in
 * the input, which is the property everything above this line does not have
 * and which turns out to be the one that matters:
 *
 *   - the headers still describe the object, so the view parses as what it is
 *     rather than as a damaged copy;
 *   - the REGIONS still line up, so a rule that declared scan_range_data is
 *     searching the bytes it meant;
 *   - and cure_patch, kof_find_str_at and every module that reads a layout at
 *     a displacement address the same byte in the view as in the original.
 *
 * WHAT IT DOES. A run of UTF-16LE ASCII is packed to the left and the rest of
 * the run is filled with zeros:
 *
 *     41 00 42 00 43 00   ->   41 42 43 00 00 00
 *
 * The fill cannot invent a match. A literal pattern contains no zero byte - see
 * the note above on ksigbuilder's six escapes - so nothing can match across the
 * fill, and a FULLWORD match that ends at the last character sees a zero beside
 * it, which is not a word byte and is the right answer.
 *
 * WHY COLLAPSING ZERO RUNS IS NOT HERE. It cannot be: removing bytes moves
 * every byte after them, and that is exactly what this exists not to do. The
 * 1-3% it saved was never the reason for any of this.
 *
 * Returns non-zero when something was rewritten, 0 when the object had no wide
 * text and the view would be a copy - and then no view should be made.
 */
int kof_exe_unwide(const uint8_t *in, uint64_t n, uint8_t *out);

/*
 * THE OTHER HALF OF THE PROMISE AT THE TOP OF THIS FILE: a base64 payload said
 * as what it decodes to, IN PLACE, on a buffer kof_exe_unwide has already
 * written.
 *
 * It is length preserving in exactly the way unwide is. Four encoded characters
 * carry three bytes, so a decoded run is always SHORTER than the run it came
 * from; the decoded bytes go at the run's own offset and the remainder is
 * zeroed. Nothing after the run moves, which is what keeps the view one to one
 * with the parent and the region table still true of it.
 *
 *
 * WHERE THIS CAME FROM, AND WHY IT IS HERE RATHER THAN IN A MODULE.
 *
 * bases/decomp/cmdb64_00.c did this as an unpacker: it found the payload of
 *
 *     echo <base64> | base64 -d | sh
 *
 * inside an ELF's .rodata and handed the decoded bytes back as a CHILD OBJECT.
 * The finding logic below is that module's, unchanged - the anchor, the walk
 * back over the pipe, the alphabet run, the `=` rule and the delimiter check
 * are all its reasoning and all of it was measured against real droppers.
 *
 * What changes is what is done with the answer. A child is a whole object: it
 * is identified, parsed, given its own budget, its own row in the tree and its
 * own pass through every module. That is a great deal of machinery for what is
 * usually a second shell command, and it is a second answer to the question
 * this file exists to answer - "say this object plainly" - given in a different
 * shape by a different layer.
 *
 * As a rewrite it costs one pass and no object, and the decoded command is
 * matched by the ordinary rules at the ordinary place.
 *
 *
 * WHAT IS GIVEN UP, SAID PLAINLY BECAUSE IT IS REAL.
 *
 * A payload that is itself an executable was PARSED as one when it was a child
 * - it got an ELF header walk, its own regions and the modules that target ELF.
 * Decoded into the middle of a view it is bytes, and only patterns find it. The
 * module's own note says the common payload is a shell command rather than a
 * binary, so this is the uncommon case, but it is a loss and not a wash.
 *
 *
 * IDEMPOTENT, which norm_emit relies on.
 *
 * A decoded run is strictly shorter than its source, so at least one byte at
 * the end of the run is left zero. The backward alphabet walk starts there,
 * stops at once, and the run is below the minimum - so a second pass over an
 * already-decoded buffer finds nothing to do.
 */
int kof_exe_unb64(uint8_t *p, uint64_t n);

uint64_t kof_exe_norm(const uint8_t *in, uint64_t n, uint32_t ops,
		  uint8_t *out, uint64_t cap,
		  struct kof_exe_norm_span *spans, uint32_t span_cap,
		  uint32_t *n_spans);

/*
 * AN OUTPUT OFFSET, AS AN INPUT OFFSET.
 *
 * For a report that has a finding at `dst` in the normalised view and has to
 * say where in the file that is. Returns non-zero and fills `src`; zero when
 * `dst` is past the output or the spans do not cover it.
 */
int kof_exe_norm_src_of(const struct kof_exe_norm_span *spans, uint32_t n_spans,
		    uint64_t dst, uint64_t *src);

#endif /* KOFENG_NORMALIZE_EXECUTABLES_H */
