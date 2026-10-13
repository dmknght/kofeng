/*
 * status.c - the one thing every part shares that is not a header.
 *
 * A name per status, for tools and for test output. Not in the header as an inline
 * function: it is called when something is being printed, never in a decode loop,
 * and a static table in every translation unit that includes the header is a copy
 * per file to save a call that nothing hot makes.
 */

#include "status.h"

const char *kuncoat_status_name(enum kuncoat_status status)
{
	switch (status) {
	case KUNCOAT_OK:        return "ok";
	case KUNCOAT_STOPPED:   return "stopped";
	case KUNCOAT_TRUNCATED: return "truncated";
	case KUNCOAT_CORRUPT:   return "corrupt";
	case KUNCOAT_UNSUPPORTED: return "unsupported";
	case KUNCOAT_OVER_BUDGET: return "over budget";
	case KUNCOAT_BAD_ARG:   return "bad argument";
	default:                return "?";
	}
}
