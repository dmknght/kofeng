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
 * WHY COLLAPSING ZERO RUNS IS NOT IN THIS FUNCTION. Removing bytes moves every
 * byte after them, and this pass has to be usable on a buffer whose offsets
 * still mean something - so the collapse is kof_exe_norm, run afterwards, and
 * the caller decides whether it wants a shorter view or the parent's offsets.
 * norm_emit wants both, in that order, and says why.
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
 * zeroed. Nothing after the run moves.
 *
 * That is a property of THIS pass, not of the finished view: norm_emit runs
 * kof_exe_norm after it and that one does move bytes. The reason to keep this
 * pass 1:1 anyway is the same reason unwide is - it must be usable on its own,
 * on a span, by a caller that still needs the parent's offsets.
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
/* A stretch of the buffer a decode pass wrote. The layered driver uses these to
 * look only where something changed - see kof_exe_decode. */
struct kof_exe_span {
	uint64_t off, len;
};

int kof_exe_unb64(uint8_t *p, uint64_t n);

/*
 * HEX TEXT SAID AS THE BYTES IT SPELLS, in place and length preserving in the
 * same way kof_exe_unb64 is: two characters carry one byte, so the decode goes
 * at the run's own offset and the rest of the run is zeroed.
 *
 * WHY THIS IS SAFE WITHOUT AN ANCHOR, WHICH BASE64 COULD NOT BE.
 *
 * The base64 module refused to hunt for base64-shaped runs because that
 * alphabet is also the alphabet of identifiers. Hex is sixteen characters, and
 * three further tests do the work an anchor would:
 *
 *   EVERY DECODED BYTE IS PRINTABLE. A hash, a build id or a long decimal
 *   decodes to arbitrary bytes and is refused; a command decodes to a command.
 *   DELIMITED. The run follows a NUL, a space, a quote or a bracket, the same
 *   rule and for the same reason as a base64 payload: it is an argument.
 *   TWENTY-FOUR CHARACTERS. Twelve bytes.
 *
 * MEASURED, because each of those numbers is a trade and none of them is
 * obvious:
 *
 *     b086aa80... (Mirai)   31 of 31 runs decoded
 *     835 ELF from /usr/bin  874 runs, 0 decoded
 *
 * At sixteen characters five clean files decoded; the four that survived the
 * printable test at twenty-four were all "2222..." preceded by '!', and the
 * delimiter rule is what removes them.
 *
 * WHAT IT DELIBERATELY DOES NOT CATCH: hex that spells SHELLCODE, or any other
 * binary. Those decode to non-printable bytes and are refused by the first test
 * above. Lifting it is not a matter of loosening the rule - a SHA-256 in hex is
 * sixty-four characters of exactly that shape, and build ids are everywhere -
 * so it needs a floor of its own, measured on its own, and it is not here.
 *
 * AND NOT AN ALPHABETIC TEST, which was tried. Requiring the decoded bytes to
 * be mostly letters loses 23 of the 31 - every C2 address in the file, because
 * "37.187.154.79" and "\n0.0.0.0 136.243.89.164" contain no letter at all.
 */
int kof_exe_unhex(uint8_t *p, uint64_t n);

/*
 * EVERY LAYER, not just the first, and each round looking only where the last
 * one wrote.
 *
 * A payload is decoded into the object, and what comes out can be encoded
 * again - base64 inside hex, hex inside base64, a second base64 inside the
 * first. One pass finds the outermost layer and stops.
 *
 * SCANNING THE WHOLE OBJECT EACH ROUND IS THE OBVIOUS WAY AND IT IS WASTE. The
 * only bytes that can hold a layer nobody has seen are the bytes the previous
 * round produced - everything else was already searched and answered. So each
 * pass records what it wrote, and the next round walks those stretches and
 * nothing else. The first round is the whole object; every round after it is
 * the size of what was decoded, which is a fraction of it.
 *
 * Returns non-zero if any layer was decoded.
 */
int kof_exe_decode(uint8_t *p, uint64_t n);

/*
 * PARENT OFFSETS TO VIEW OFFSETS, for a sorted list of them, in one pass.
 *
 * What a caller needs to carry a REGION TABLE onto the view. A shortened view
 * is not the executable its headers describe, so nothing can parse regions out
 * of it - they have to be brought across from the parent, and bringing them
 * across is this.
 *
 * `src` must be ascending; `dst` takes k answers. Both the transform and the
 * ops must be the ones the view was made with, or the answers are about a
 * different view. See the note above the definition for what an offset inside
 * a collapsed run returns.
 */
void kof_exe_norm_map(const uint8_t *in, uint64_t n, uint32_t ops,
		      const uint64_t *src, uint64_t *dst, uint32_t k);

/*
 * THE TRANSFORM WITH REGIONS THAT MUST NOT MOVE.
 *
 * `keep` is a bitmap over the input, one bit per byte, set where the byte must
 * appear in the view unchanged and at no cost to anything after it. NULL means
 * nothing is kept, which is kof_exe_norm's behaviour.
 *
 * WHAT IS KEPT AND WHY IT IS NOT A STYLE CHOICE:
 *
 *   HEADERS  Nothing else can be kept unless this is. An ELF's e_ident carries
 *            eight zeros at offset 8 and collapsing them moved e_machine from
 *            18 to 12 - the view came back with no architecture and a parse
 *            that found children that are not there.
 *
 *   CODE     Opcodes are what a hex rule is written against, byte for byte,
 *            and an instruction stream has no encoded text in it to reveal.
 *            There is nothing to gain here and an offset to lose.
 *
 * and everything else - data, the sections the loader ignores, the unclaimed
 * gaps, an overlay - is rewritten, because that is where the padding, the wide
 * text and the encoded payloads are.
 *
 * Symbol regions need no mention: KOF_SCAN_SYM_* are extents over the canonical
 * RECORDS, not over the file, so no byte of the input is ever theirs.
 *
 * `mark`/`mark_out` carry a sorted list of parent offsets through to their view
 * positions in the same pass - see the note above the definition.
 *
 * Returns the view length, or 0 when nothing was rewritten.
 */
uint64_t kof_exe_norm_masked(const uint8_t *in, uint64_t n, const uint8_t *keep,
			     uint32_t ops, uint8_t *out, uint64_t cap,
			     const uint64_t *mark, uint64_t *mark_out,
			     uint32_t n_mark);

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
