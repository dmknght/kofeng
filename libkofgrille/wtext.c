/*
 * wtext.c - see wtext.h for why this is not inside wevt_decode.c.
 *
 * No Windows header is included here and none may be: this file and
 * wevt_ring.c and wfilter.c are what a host without ETW can compile and run,
 * and that is the whole of the library's test surface.
 */

#include <string.h>

#include "kofgrille.h"
#include "wtext.h"

/* See kofw_evt_to_kof: the conversion may not shorten a path, and this is what
 * makes that true rather than likely. */
_Static_assert(KOFW_REC_SIZE - KOFW_REC_HEAD <= KOF_EVT_SIZE - KOF_EVT_HEAD,
	       "the neutral record's text arena is smaller than the "
	       "collector's - a conversion would silently truncate paths");


size_t kofw_bytes_to_text(const uint8_t *src, size_t n, char *dst,
			  size_t dst_cap, int *cut)
{
	size_t i, o = 0;

	if (cut)
		*cut = 0;
	if (!dst || dst_cap == 0)
		return 0;

	for (i = 0; i < n; i++) {
		uint8_t b = src[i];

		if (o + 1 >= dst_cap) {
			if (cut)
				*cut = 1;
			break;
		}
		/* A NUL becomes a dot rather than an ending - see wtext.h. */
		if (b < 0x20u || b == 0x7fu)
			b = (uint8_t)'.';
		else if (b >= 0x80u)
			b = (uint8_t)'?';
		dst[o++] = (char)b;
	}

	dst[o] = '\0';
	return o;
}

/* ------------------------------------------------------------------ UTF-16 */

/*
 * Written out rather than calling WideCharToMultiByte, for two reasons that
 * both matter here. It runs per record on the ETW callback thread, and the
 * Win32 call carries codepage and locale machinery this does not need; and a
 * plain-C conversion is what lets it be tested on a host that has no Windows
 * API at all. See wtext.h.
 */
size_t kofw_utf16_to_utf8(const uint16_t *src, size_t src_chars,
			  char *dst, size_t dst_cap, int *cut)
{
	size_t i = 0, o = 0;

	if (cut)
		*cut = 0;
	if (!dst || dst_cap == 0)
		return 0;

	while (i < src_chars) {
		uint32_t cp = src[i++];

		if (cp == 0)
			break;

		/* A surrogate pair, when the low half is actually there. A lone
		 * half is not an error to reject the whole path over - it is
		 * passed through as U+FFFD so the rest of the name survives. */
		if (cp >= 0xd800u && cp <= 0xdbffu) {
			if (i < src_chars && src[i] >= 0xdc00u &&
			    src[i] <= 0xdfffu) {
				uint32_t lo = src[i++];
				cp = 0x10000u + ((cp - 0xd800u) << 10) +
				     (lo - 0xdc00u);
			} else {
				cp = 0xfffdu;
			}
		} else if (cp >= 0xdc00u && cp <= 0xdfffu) {
			cp = 0xfffdu;
		}

		/*
		 * C0 and DEL become '.', for the reason the engine sanitises an
		 * archive entry name: this string is chosen by whoever created
		 * the file and it is printed to a terminal, and an escape
		 * sequence inside it is a report that lies about what it says.
		 */
		if (cp < 0x20u || cp == 0x7fu)
			cp = (uint32_t)'.';

		if (cp < 0x80u) {
			if (o + 1 >= dst_cap)
				goto full;
			dst[o++] = (char)cp;
		} else if (cp < 0x800u) {
			if (o + 2 >= dst_cap)
				goto full;
			dst[o++] = (char)(0xc0u | (cp >> 6));
			dst[o++] = (char)(0x80u | (cp & 0x3fu));
		} else if (cp < 0x10000u) {
			if (o + 3 >= dst_cap)
				goto full;
			dst[o++] = (char)(0xe0u | (cp >> 12));
			dst[o++] = (char)(0x80u | ((cp >> 6) & 0x3fu));
			dst[o++] = (char)(0x80u | (cp & 0x3fu));
		} else {
			if (o + 4 >= dst_cap)
				goto full;
			dst[o++] = (char)(0xf0u | (cp >> 18));
			dst[o++] = (char)(0x80u | ((cp >> 12) & 0x3fu));
			dst[o++] = (char)(0x80u | ((cp >> 6) & 0x3fu));
			dst[o++] = (char)(0x80u | (cp & 0x3fu));
		}
	}

	dst[o] = '\0';
	return o;

full:
	if (cut)
		*cut = 1;
	dst[o] = '\0';
	return o;
}

/* The same, for a payload that carries its string as bytes rather than UTF-16 -
 * which Kernel-Process does for ProcessStop's ImageName. See wtext.h. */
size_t kofw_ansi_to_text(const uint8_t *src, size_t n, char *dst,
			 size_t dst_cap, int *cut)
{
	size_t i, o = 0;

	if (cut)
		*cut = 0;
	if (!dst || dst_cap == 0)
		return 0;

	for (i = 0; i < n; i++) {
		uint8_t b = src[i];

		if (b == 0)
			break;
		if (o + 1 >= dst_cap) {
			if (cut)
				*cut = 1;
			break;
		}
		if (b < 0x20u || b == 0x7fu)
			b = (uint8_t)'.';
		else if (b >= 0x80u)
			b = (uint8_t)'?';
		dst[o++] = (char)b;
	}

	dst[o] = '\0';
	return o;
}

/* --------------------------------------------------- reading a record back */

/*
 * THE THREE ACCESSORS, AND WHY THEY ARE ON THIS SIDE OF THE LINE.
 *
 * They were in wevt_decode.c, which opens with #include <windows.h> - and
 * wfilter.c calls two of them. So the "no Windows API in it, deliberately"
 * half of this library did not LINK without the half that is all Windows API,
 * and the test that was supposed to prove the boundary existed is what found
 * that it did not. A boundary nothing links across is the only kind there is.
 *
 * They belong here on their own merits too: all three do is read the record's
 * text arena and its type, which is what this file is about, and none of them
 * needs a provider, a session or a schema to do it.
 */

const char *kofw_evt_image(const struct kofw_evt *e)
{
	if (!e || e->off_image == KOF_TEXT_NONE ||
	    e->off_image >= sizeof e->text)
		return "";
	return e->text + e->off_image;
}

const char *kofw_evt_cmdline(const struct kofw_evt *e)
{
	if (!e || e->off_cmdline == KOF_TEXT_NONE ||
	    e->off_cmdline >= sizeof e->text)
		return "";
	return e->text + e->off_cmdline;
}

const char *kofw_evt_object(const struct kofw_evt *e)
{
	if (!e || e->off_object == KOF_TEXT_NONE ||
	    e->off_object >= sizeof e->text)
		return "";
	return e->text + e->off_object;
}


const char *kofw_provider_name(uint8_t prov)
{
	switch (prov) {
	case KOFW_PROV_PROCESS: return "process";
	case KOFW_PROV_FILE:    return "file";
	case KOFW_PROV_NET:     return "net";
	case KOFW_PROV_REGISTRY: return "registry";
	/*
	 * Missing here for a whole debugging session, and it cost the answer to
	 * "is AMSI arriving at all". Its records were printing as `[? id 1101]`
	 * and were read as some unknown provider's noise - so a source that was
	 * working the whole time looked like one that had never been enabled.
	 *
	 * A `default` that returns "?" for a value the enum HAS is worse than
	 * one that returns "?" for a value it does not: the first hides a
	 * working path.
	 */
	case KOFW_PROV_AMSI:    return "amsi";
	default:                return "?";
	}
}

const char *kofw_sub_name(uint32_t one_bit)
{
	switch (one_bit) {
	case KOFW_SUB_PROCESS:    return "process";
	case KOFW_SUB_IMAGE:      return "image";
	case KOFW_SUB_FILE:       return "file";
	case KOFW_SUB_FILE_WRITE: return "file-write";
	case KOFW_SUB_NET:        return "net";
	case KOFW_SUB_REGISTRY:   return "registry";
	case KOFW_SUB_THREAD:     return "thread";
	case KOFW_SUB_FILE_OPEN:  return "file-open";
	case KOFW_SUB_AMSI:       return "amsi";
	default:                  return "";
	}
}

/* ------------------------------------------- to the neutral record */

/*
 * See kofgrille.h for why this direction and not the other.
 *
 * The text arena is copied WHOLE and the offsets carried across, rather than
 * re-appending three strings. Two reasons: the offsets are already consistent
 * with each other, and re-appending would silently re-truncate a record that
 * had already been cut - turning one KOF_EF_TRUNCATED into two different
 * strings, neither of which is what was collected.
 */
void kofw_evt_to_kof(const struct kofw_evt *in, struct kof_evt *out)
{
	size_t n;

	if (!in || !out)
		return;

	memset(out, 0, sizeof *out);

	out->stamp       = in->stamp;
	out->seq         = in->seq;
	out->create_time = in->create_time;
	out->addr        = in->addr;
	out->addr_size   = in->addr_size;

	out->pid         = in->pid;
	out->ppid        = in->ppid;
	/* The name changes because the meaning is worth stating once: it is
	 * who CAUSED the event, which for an injection is the whole answer. */
	out->actor_pid   = in->raiser_pid;
	out->tid         = in->tid;
	out->session_id  = in->session_id;
	out->exit_code   = in->exit_code;
	out->miss        = in->miss;

	out->net_daddr   = in->net_daddr;
	out->net_saddr   = in->net_saddr;
	out->net_size    = in->net_size;
	out->net_dport   = in->net_dport;
	out->net_sport   = in->net_sport;

	out->verb        = in->type;
	out->attack      = in->attack;
	out->raw_id      = in->raw_id;
	out->loc         = in->obj_loc;
	out->flags       = in->flags;
	out->os          = KOF_OS_WINDOWS;

	/*
	 * THE WHOLE ARENA SURVIVES, AND THAT IS ASSERTED RATHER THAN HOPED.
	 *
	 * The static assert below is the real guarantee: the neutral record's
	 * arena is at least as large as this collector's, so a conversion can
	 * never shorten a path. It is worth an assertion because the two
	 * headers grow independently - this one gained a command line, that one
	 * gained an attack id - and the day one overtakes the other, a silent
	 * truncation would start producing paths that look whole.
	 *
	 * The clamp is kept anyway, for the case where somebody changes a
	 * header and the assert is what tells them. If it ever runs, the record
	 * says so: a path shortened without saying so is what a later rule
	 * matches and is wrong about.
	 */
	n = in->text_len;
	if (n > sizeof out->text) {
		n = sizeof out->text;
		out->flags |= KOF_EF_TRUNCATED;
	}
	memcpy(out->text, in->text, n);
	out->text_len = (uint16_t)n;

	/* An offset that fell outside what was copied becomes absent, which is
	 * the only honest answer - the bytes it pointed at are not here. */
	out->off_image   = (in->off_image   < n) ? in->off_image   : KOF_TEXT_NONE;
	out->off_object  = (in->off_object  < n) ? in->off_object  : KOF_TEXT_NONE;
	out->off_cmdline = (in->off_cmdline < n) ? in->off_cmdline : KOF_TEXT_NONE;
}
