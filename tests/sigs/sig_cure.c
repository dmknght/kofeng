/*
 * sig_cure - a detector that also knows how to undo what it found.
 *
 * WHY THIS EXISTS. The cure path had no test at all: the only modules carrying
 * a kof_cure were the RST rules in bases/, which need a real infected sample
 * and therefore cannot run in the suite. So the mechanism - the offer, the two
 * requests, the host's bounds on them, and the repair that comes out the other
 * side - was only ever exercised by hand.
 *
 * The damage this describes is deliberately the simplest thing that still has
 * both halves of a repair: a marker in the object says "infected", four bytes
 * at a fixed place are wrong, and there is a tail to cut. A real virus is not
 * this tidy; the point here is the PLUMBING, not the recovery.
 */

#include <kofmod/kofsig.h>

KOF_TARGET_FORMAT(KOF_FMT_UNKNOWN);
KOF_TARGET_NAME(KOF_MALTYPE_VIRUS, "CureTest");

/* The marker sits at offset 0 so the test can build the object by hand.
 * kof_find_str_at takes an OFFSET, not a range - the offset is the scope. */
KOF_DEFINE_STR(s0, "KOFCURETEST!", KOF_CASE_EXACT, KOF_WORD_SUBSTRING);

KOF_DEFINE_SCAN
{
	if (!kof_find_str_at(0u, s0))
		return;
	/*
	 * WHERE THE DAMAGE IS, which is what makes this curable. Passing the
	 * marker's own offset is enough for a test - a real rule passes the
	 * place it worked out the payload starts.
	 */
	KOF_SCAN_CURABLE(0u);
	KOF_SCAN_INFECT(KOF_MALVAR_GENERIC);
}

/*
 * The repair: put the four bytes at offset 16 back, and cut the object to 32.
 *
 * Both numbers are constants rather than something read out of the object,
 * because a test that also had to get the recovery right would be testing two
 * things and reporting one.
 */
void kof_cure(const struct kof_obj_ctx *ctx)
{
	static const uint8_t orig[4] = { 0xDE, 0xAD, 0xBE, 0xEF };

	kof_cure_patch(16u, orig, 4u);
	kof_cure_truncate(32u);

	/*
	 * AND THE REQUESTS THE HOST MUST REFUSE, asked here so the test can
	 * assert that refusing them changes nothing. A module that asks for
	 * more than sixteen bytes, or for a patch past the end, or for a
	 * truncation to nothing or to more than there is, has described
	 * something the host cannot do - and the answer is a refusal, not a
	 * clamp, because a clamped repair is a different repair.
	 */
	kof_cure_patch(16u, orig, 17u);          /* too many bytes */
	kof_cure_patch(0xffffffffu, orig, 4u);   /* past the object */
	kof_cure_truncate(0u);                   /* cut to nothing */
	kof_cure_truncate(0xffffffffu);          /* cut to more than there is */
}
