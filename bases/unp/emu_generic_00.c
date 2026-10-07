/*
 * emu_generic_00.c - the object nobody recognised, run because running it is
 * the only way left to see inside.
 *
 * WHY THIS IS A MODULE AND NOT A BRANCH IN THE ENGINE.
 *
 * An unpack module is the abstraction over HOW a thing comes apart - by
 * reading it, by running it, or by alternating - and it owns what comes out:
 * the regions, the layout, the object itself. The interpreter does not. It
 * executes hostile bytes, and a component that does that must not also be able
 * to create objects, declare regions or name anything. It gathers and reports;
 * somebody else decides.
 *
 * For a file a FAMILY module claimed, that somebody is the family module - it
 * knows what its packer's run means. This is the other case, and it has to
 * exist or the interpreter has no receiver at all: nothing recognised the
 * file, every static reader declined, and what is left is to run it and look
 * at what it wrote.
 *
 * WHAT IT DOES WITH WHAT IT FINDS is emu_harvest.h, shared with the family
 * modules that drive the interpreter for a reason of their own.
 *
 * IT ASKS LAST, AND WITHOUT VOUCHING. `kunp_opened_already` is what keeps it
 * off an object some other module has already opened, and the run is asked for
 * unvouched - so the host applies its own gate, the one about density and
 * loadability that is the only thing askable about a file nobody recognised.
 * The ceilings are the host's either way.
 */

#include <kofmod/kofsig.h>
#include <kofunpack/emu_harvest.h>

KOF_ANALYZE_STEP(KOF_ANALYZE_UNPACK);


/*
 * EVERY FORMAT, AND THE FORMATLESS. A stub that assembles a program can be
 * carried by any of them, and what it leaves behind is the same question in
 * each case.
 */
KOF_TARGET_FORMAT(KOF_FMT_PE | KOF_FMT_ELF | KOF_FMT_UNKNOWN);

void kof_unpack(const struct kof_obj_ctx *ctx)
{
	/*
	 * NOT ON SOMETHING ALREADY IN HAND. A static unpacker that opened this
	 * object has produced the thing worth looking at, and running it as
	 * well is the payload peeled and then run anyway.
	 */
	if (kunp_opened_already())
		return;

	/*
	 * UNVOUCHED, because there is nothing to vouch WITH: nothing
	 * recognised this file. The host applies its own gate - density,
	 * loadability, whether it looks like a loader - which is the only
	 * question askable about an object no module claimed.
	 */
	eh_fold(ctx, kunp_emu_run(0));
}
