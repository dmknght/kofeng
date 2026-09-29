/*
 * decomp.h - what every decompressor here reports, and why the set is what it is.
 *
 * One enum shared by all of them rather than one per decoder. The four outcomes are
 * a property of decompressing hostile input, not of any particular format, and the
 * host acts on them identically - so a second copy of this list would be a second
 * place for the meanings to drift.
 *
 * The distinction that carries weight is TRUNCATED and CORRUPT against STOPPED:
 *
 *   - TRUNCATED and CORRUPT are the STREAM failing. Whatever was decoded before the
 *     failure is real output and is worth scanning - a damaged archive inside a
 *     malware sample is the ordinary case, and refusing to look at its first
 *     megabyte because its last kilobyte is missing discards the part that
 *     identifies it. Measured on a 12GB corpus: of 285 gzip members, 35 were
 *     damaged, and every one of them still produced a usable prefix.
 *
 *   - STOPPED is the RECEIVER declining more, which is not a failure of anything.
 *     Every limit the engine has arrives here: the object cap, the total budget,
 *     the memory ceiling. Reporting it as corruption would label every object that
 *     hit a budget as a broken archive.
 *
 * A decoder never decides what any of this means. It reports, and the host decides
 * whether the object is incomplete.
 */

#ifndef KOFENG_DECOMP_H
#define KOFENG_DECOMP_H

/*
 * THE CONTRACT, WRITTEN DOWN.
 *
 * Every entry point that reports an outcome returns `enum kof_decomp_status`
 * and returns one of the values below - not an int that happens to hold one.
 * The set is CLOSED: a decoder has nothing else to say, and a caller has
 * nothing else to handle.
 *
 * This was not written anywhere, and the omission had teeth. Five of the seven
 * decoders were declared to return `int` and two the enum, all of them
 * returning the same codes. Two things followed.
 *
 * The visible one was a warning on clang and not on gcc. Every code here is
 * non-negative, so C11 lets the implementation pick any integer type that fits
 * them - clang picks an unsigned one, gcc picks int - and an `int` meeting the
 * enum type is then a signed-to-unsigned conversion on one compiler only. It is
 * tempting to cast at the call site. That hides the difference rather than
 * removing it, and leaves the next call site to rediscover it.
 *
 * The dangerous one was that "every code is non-negative" was an accident of
 * the list rather than a promise. A decoder written later returning -1 for
 * "something went wrong" would be widened through an unsigned type into an int,
 * compare equal to none of these, and compile without a word.
 *
 * So the type is pinned below, and the return types are all the enum. A stray
 * value is then still a stray value at run time - which is the honest outcome -
 * rather than a different stray value on each compiler.
 */
enum kof_decomp_status {
	KOF_DEC_OK = 0,     /* the end of the stream was reached and decoded */
	KOF_DEC_STOPPED,    /* the receiver refused more; output so far is good */
	KOF_DEC_TRUNCATED,  /* input ended mid-stream; output so far is good */
	KOF_DEC_CORRUPT,    /* the stream is not valid for its format */
	/*
	 * The stream is well formed and uses a coding this build does not have.
	 *
	 * Distinct from CORRUPT because the two want opposite reactions: a corrupt
	 * stream is a finding about the file, an unsupported one is a gap in this
	 * engine. Output produced before the point of refusal is still valid and is
	 * still reported.
	 */
	KOF_DEC_UNSUPPORTED,
	/*
	 * NOT A STATUS. It pins the underlying type, and that is all it does.
	 *
	 * One negative enumerator obliges every conformant implementation to
	 * choose a SIGNED underlying type, because the type has to represent
	 * every value in the list. So the enum is the same width and the same
	 * signedness under gcc, clang and whatever the ARM builder is using -
	 * and a value that is not a status stays the value it was instead of
	 * becoming a large positive number on some builds.
	 *
	 * C11 has no way to say `enum ... : int`; C23 does. When this codebase
	 * moves to C23 this enumerator is what gets deleted, and the fixed
	 * underlying type is what replaces it.
	 *
	 * Never returned, never handled: it is covered by the same `default`
	 * that covers any other value that is not a status.
	 */
	KOF_DEC__PIN_SIGNED = -1
};

/*
 * The status as a word, for a message.
 *
 * Takes the enum rather than an int so that passing something that is not a
 * status is a conversion somebody wrote on purpose. Out-of-set values are
 * answered "?" rather than refused - this is called on a failure path, and a
 * diagnostic that cannot itself fail is worth more there than one that
 * validates its argument.
 */
const char *kof_decomp_status_name(enum kof_decomp_status status);

#endif /* KOFENG_DECOMP_H */
