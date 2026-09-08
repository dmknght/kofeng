/*
 * wtext.c - see wtext.h for why this is not inside wevt_decode.c.
 *
 * No Windows header is included here and none may be: this file and
 * wevt_ring.c and wfilter.c are what a host without ETW can compile and run,
 * and that is the whole of the library's test surface.
 */

#include "kofgrille.h"
#include "wtext.h"


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
	if (!e || e->off_image == KOFW_TEXT_NONE ||
	    e->off_image >= sizeof e->text)
		return "";
	return e->text + e->off_image;
}

const char *kofw_evt_object(const struct kofw_evt *e)
{
	if (!e || e->off_object == KOFW_TEXT_NONE ||
	    e->off_object >= sizeof e->text)
		return "";
	return e->text + e->off_object;
}

const char *kofw_evt_type_name(uint16_t type)
{
	switch (type) {
	case KOFW_EVT_PROC_START: return "ProcStart";
	case KOFW_EVT_PROC_STOP:  return "ProcStop";
	case KOFW_EVT_IMAGE_LOAD: return "ImageLoad";
	case KOFW_EVT_FILE_NEW:   return "FileNew";
	case KOFW_EVT_FILE_DELETE: return "FileDel";
	case KOFW_EVT_FILE_RENAME: return "FileRen";
	case KOFW_EVT_NET_CONNECT:    return "NetConn";
	case KOFW_EVT_NET_SEND:       return "NetSend";
	case KOFW_EVT_NET_RECV:       return "NetRecv";
	case KOFW_EVT_NET_DISCONNECT: return "NetClose";
	case KOFW_EVT_IMAGE_UNLOAD:   return "ImgUnload";
	case KOFW_EVT_FILE_WRITE:     return "FileWrite";
	case KOFW_EVT_REG_CREATE:     return "RegNew";
	case KOFW_EVT_REG_SET_VALUE:  return "RegSet";
	case KOFW_EVT_REG_DELETE:     return "RegDel";
	case KOFW_EVT_THREAD_START:   return "ThreadNew";
	case KOFW_EVT_THREAD_STOP:    return "ThreadEnd";
	case KOFW_EVT_RAW:        return "raw";
	default:                  return "?";
	}
}

const char *kofw_provider_name(uint8_t prov)
{
	switch (prov) {
	case KOFW_PROV_PROCESS: return "process";
	case KOFW_PROV_FILE:    return "file";
	case KOFW_PROV_NET:     return "net";
	case KOFW_PROV_REGISTRY: return "registry";
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
	default:                  return "";
	}
}
