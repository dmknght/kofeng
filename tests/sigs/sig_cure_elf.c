/*
 * sig_cure_elf - an appending infection of a real ELF, and the repair for it.
 *
 * WHY A SECOND CURE RULE. sig_cure proves the PLUMBING: the offer, the two
 * requests, the host's bounds on them. It does that on bytes with no format,
 * which is the right scope for the plumbing and the wrong scope for the claim
 * that matters - that a file which has been cured still RUNS.
 *
 * So this one works on an ELF, and the shape it undoes is the one an appending
 * virus really uses:
 *
 *     the payload is appended past the original end;
 *     e_entry is pointed at it;
 *     it opens with a jump over its own data, because a marker at the entry is
 *     a marker the processor would otherwise execute;
 *     the original entry and the original length are kept in that data, so the
 *     virus can hand control back.
 *
 * A REPAIR AND NOT A REBUILD. Two fields go back to what they were and the
 * tail is cut. Nothing here reconstructs a program header table, recomputes a
 * section table or moves a segment - a rebuild produces a file that resembles
 * the original, and only a repair produces the original. The test executes
 * what comes out, which is the only check that tells those two apart.
 */

#include <kofmod/kofsig.h>

KOF_TARGET_FORMAT(KOF_FMT_ELF);
KOF_TARGET_NAME(KOF_MALTYPE_VIRUS, "CureElfTest");

/*
 * The payload's own signature, at the entry point rather than anywhere in the
 * file: an ELF that merely CONTAINS these bytes is not one that RUNS them, and
 * the difference is what separates an infected host from a dropper carrying a
 * copy - see bases/signatures/rst_00.c, which is the real instance of this.
 */
KOF_DEFINE_STR(mark, "KOFINFECT", KOF_CASE_EXACT, KOF_WORD_SUBSTRING);

KOF_DEFINE_SCAN
{
	if (ctx->entry_off == KOF_NA || ctx->entry_off == KOF_BROKEN)
		return;
	/* Past the two byte jump the payload opens with - see the note. */
	if (!kof_find_str_at(ctx->entry_off + 2u, mark))
		return;
	KOF_SCAN_CURABLE(ctx->entry_off);
	KOF_SCAN_INFECT(KOF_MALVAR_GENERIC);
}

/*
 * The payload keeps what it displaced, immediately after its marker:
 *
 *     +0   jmp over the data  2 bytes
 *     +2   "KOFINFECT"        9 bytes
 *     +11  original e_entry   4 bytes, little endian
 *     +15  original length    4 bytes, little endian
 *
 * Both are read back out of the object rather than assumed, which is what
 * makes this a repair: the numbers come from the file being repaired and not
 * from the rule.
 */
void kof_cure(const struct kof_obj_ctx *ctx)
{
	uint64_t at = ctx->entry_off;
	uint64_t entry, len;
	uint8_t  b[4];

	if (at == KOF_NA || at == KOF_BROKEN)
		return;

	entry = kof_u32(at + 11u);
	len   = kof_u32(at + 15u);

	/*
	 * REFUSED RATHER THAN APPLIED HALF WAY. A payload that names a length
	 * the object does not have is not one this rule understands, and
	 * putting one of the two numbers back would leave a file that is
	 * neither infected nor the original.
	 *
	 * THE ENTRY IS A VIRTUAL ADDRESS AND THE LENGTH IS A FILE OFFSET, and
	 * the first version of this checked `entry >= len` - which is the two
	 * measured against each other and is always true: an entry of 0x400078
	 * is not "past" a file of 132 bytes, it is in a different unit. The
	 * cure silently did nothing and the test said so.
	 */
	if (!len || len > ctx->obj_size || !entry)
		return;

	b[0] = (uint8_t)entry;
	b[1] = (uint8_t)(entry >> 8);
	b[2] = (uint8_t)(entry >> 16);
	b[3] = (uint8_t)(entry >> 24);

	/* e_entry sits at 24 in an ELF64 header - the test builds one. */
	if (!kof_cure_patch(24u, b, 4u))
		return;

	/*
	 * AND THE SEGMENT THE VIRUS GREW, which is the half that "it runs" does
	 * not catch.
	 *
	 * An appending virus does not only move e_entry: it widens the PT_LOAD
	 * so its own bytes are mapped. Putting the entry back and cutting the
	 * tail leaves a program header still claiming the longer length, and a
	 * file whose segment runs past its own end - which EXECUTES perfectly
	 * well, because the kernel maps what is there, and is still damaged.
	 * The engine says so: without this the cured file came back
	 * Heur:Truncated, which is the right answer to a segment that is not
	 * all there. bases/signatures/rst_00.c does the same thing for the same
	 * reason.
	 *
	 * p_filesz and p_memsz are adjacent - 32 and 40 of an ELF64 program
	 * header - so both go back in one sixteen byte patch. The test's ELF
	 * has one PT_LOAD covering the whole file, so the length they return
	 * to is the file's.
	 */
	{
		uint64_t phoff = kof_u32(32u);
		uint8_t  sz[16];
		unsigned i;

		if (!phoff)
			return;
		for (i = 0; i < 8u; i++) {
			sz[i]      = (uint8_t)(len >> (8u * i));
			sz[8u + i] = sz[i];
		}
		if (!kof_cure_patch(phoff + 32u, sz, 16u))
			return;
	}
	kof_cure_truncate(len);
}
