/*
 * decomp.c - the one thing every decompressor shares that is not a header.
 *
 * A name per status, for tools and for test output. Not in the header as an inline
 * function: it is called when something is being printed, never in a decode loop,
 * and a static table in every translation unit that includes the header is a copy
 * per file to save a call that nothing hot makes.
 */

#include "decomp.h"

const char *kof_decomp_status_name(int status)
{
	switch (status) {
	case KOF_DEC_OK:        return "ok";
	case KOF_DEC_STOPPED:   return "stopped";
	case KOF_DEC_TRUNCATED: return "truncated";
	case KOF_DEC_CORRUPT:   return "corrupt";
	case KOF_DEC_UNSUPPORTED: return "unsupported";
	default:                return "?";
	}
}
