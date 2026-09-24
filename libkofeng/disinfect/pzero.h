/*
 * pzero.h - the arithmetic a cure is made of.
 *
 * WHY THIS IS A STAGE OF ITS OWN.
 *
 * The extractor produces objects, the detector decides about them, and this
 * reverses what was done to one. The three are peers and this is the only one
 * that is allowed to say a file should CHANGE, which is exactly the reason it
 * is not folded into either of the others: a stage that both decides and
 * repairs can repair on the strength of its own opinion.
 *
 *
 * IT COMPUTES AND DESCRIBES. IT DOES NOT WRITE.
 *
 * Nothing here opens a file, truncates one, or changes a mode. A cure is a
 * REQUEST - kof_cure_patch and kof_cure_truncate in kofcure.h - which the host
 * records, bounds-checks and may refuse; see c_cure_patch in objctx.c, where
 * the bound is enforced because a rule that could name an offset past the end
 * of the object is a rule that could corrupt a file the engine was asked to
 * look at. What is here works out WHICH request to make.
 *
 * That line is also why the numbers below are returned rather than applied. A
 * caller that wants to show a repair before carrying it out reads the same
 * answers the caller that carries it out does.
 *
 *
 * WHY "pzero".
 *
 * Patient zero: the host as it was before it was infected. Everything here
 * answers one question - what did this file look like before - and answers it
 * from the file itself rather than from a copy nobody has.
 *
 *
 * WHAT A CURE IS ALLOWED TO BE BUILT FROM, and it is a short list.
 *
 * Measured over 1312 cure objects in Kaspersky's own bases (dmknght_sig_
 * collectors): 59.4% of them call three or fewer engine primitives and 82.0%
 * call five or fewer. A cure is not a program, it is a formula with the
 * host's own numbers in it. The families that turned up, by how many cure
 * objects touched each:
 *
 *   parse facts   85.8%   header, entry, file length, overlay, subtype
 *   page reads    86.2%   the bytes at a place the parse named
 *   size change   43.0%   truncate, move data up, add, delete
 *   fill / mask   31.5%   fill a range, copy a range, xor a range
 *   read / write  27.2% / 25.7%
 *
 * The whole point of the list is that a cure never GUESSES a number. Every
 * one of them is read out of the object: the length the virus stored, the
 * entry it saved, the end of the last region the parse claims. A size derived
 * from alignment arithmetic, or an entry recovered by disassembling until
 * something looks like a prologue, is a guess - and a guess that truncates a
 * file is how a repair destroys one.
 */
#ifndef KOF_PZERO_H
#define KOF_PZERO_H

#include <stdint.h>

struct kof_obj_ctx;

/*
 * WHERE THE HOST'S OWN BYTES END, which is where an appended body begins.
 *
 * The largest end offset any region the parse claims reaches. A parasitic
 * infector that appends puts its body past all of them, so this is the
 * truncation point - and it is a FACT of the parse rather than a guess at
 * alignment.
 *
 * KOF_BROKEN when the object was not parsed into regions, which is the answer
 * that stops a caller truncating on nothing.
 */
uint64_t kof_pz_clean_end(const struct kof_obj_ctx *ctx);

/*
 * DOES THIS PLACE HOLD INSTRUCTIONS, asked of the parse and not of the bytes.
 *
 * The check every entry-point restore needs: a value recovered out of a stub
 * is only an entry point if it lands where code lives.
 *
 * Measured on 127 files sharing one entry stub, the address the stub had
 * saved equalled the host's own .text in 125 of them - so the test separates
 * a recovered entry from a number that merely parsed. Note what that measures
 * and what it does not: those files share a stub, which says the same tool
 * touched all of them. It does NOT say the tool replicated - a protector its
 * author ran over a toolkit leaves the same trace as an infector, and the
 * same restore puts both back.
 *
 * `off` is a file offset in this object, not an address.
 */
int kof_pz_is_code(const struct kof_obj_ctx *ctx, uint64_t off);

/*
 * AN ADDRESS THE FILE USES, AS AN OFFSET INTO IT.
 *
 * A saved entry point is an address; every request a cure makes is an offset.
 * PE answers this from its section table and ELF from its program headers,
 * and doing it here rather than in each rule is what stops a module
 * dispatching on format.
 *
 * KOF_BROKEN when no region of the file is mapped there.
 */
uint64_t kof_pz_addr_to_off(const struct kof_obj_ctx *ctx, uint64_t addr);

/*
 * THE MASK A VIRUS PUT OVER THE BYTES IT SAVED.
 *
 * The header a parasitic infector keeps so it can put it back is often kept
 * encrypted - the simplest thing that stops a scanner matching the original.
 * Kaspersky's cure objects reach for exactly three shapes and no others:
 * byte xor (143 of 1312), word xor (83) and a rotate; `add` is the same
 * family. So the set is closed, and it is closed on purpose: a cure that
 * needed a cipher would be a cure whose key had to be recovered, which
 * belongs in an unpacker.
 */
enum kof_pz_mask {
	KOF_PZ_MASK_NONE = 0,
	KOF_PZ_MASK_XOR8,
	KOF_PZ_MASK_XOR16,
	KOF_PZ_MASK_ADD8,
	KOF_PZ_MASK_ROL8
};

/*
 * Unmask `n` bytes of `in` into `out`, which the caller owns. Returns the
 * bytes written, 0 when the mask is not one of the above or n is 0.
 *
 * OUT OF PLACE, because the input is the object's own buffer and the object
 * is not this stage's to edit - see the note at the top.
 */
uint32_t kof_pz_unmask(const uint8_t *in, uint32_t n, uint32_t mask,
		       uint32_t key, uint8_t *out, uint32_t cap);

/*
 * THE PE CHECKSUM, over a buffer that already holds the repair.
 *
 * Only a driver or a system binary has one that matters, and a repair that
 * changes a header without it leaves a file Windows will refuse to load. The
 * field itself must read zero while the sum is taken, which is the caller's
 * to arrange - this does not write to the buffer.
 */
uint32_t kof_pz_pe_checksum(const uint8_t *p, uint64_t n, uint64_t csum_off);

#endif /* KOF_PZERO_H */
