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

enum kof_decomp_status {
	KOF_DEC_OK = 0,     /* the end of the stream was reached and decoded */
	KOF_DEC_STOPPED,    /* the receiver refused more; output so far is good */
	KOF_DEC_TRUNCATED,  /* input ended mid-stream; output so far is good */
	KOF_DEC_CORRUPT     /* the stream is not valid for its format */
};

const char *kof_decomp_status_name(int status);

#endif /* KOFENG_DECOMP_H */
