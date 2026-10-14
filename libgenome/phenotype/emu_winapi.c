/*
 * emu_winapi.c - the Windows environment: what each emulated API does when the guest calls it.
 * Part of the interpreter; see emu_interp.c and emu_private.h.
 */
#define _POSIX_C_SOURCE 199309L

#include "emu_private.h"

/*
 * the sockets of the scripted peer.
 *
 * One arm of the dispatch in kgenome_emu_winapi_do, moved out so the dispatch stays readable.
 * Sets *mine to 0 for an id that is not one of its own.
 */
static uint64_t win_net(struct kgenome_emu *e, unsigned id, int *mine)
{
	*mine = 1;
	switch (id) {
	case KGENOME_EMU_WIN_WSAStartup: {
		uint64_t d = kgenome_emu_win_arg(e, 1);
		uint16_t ver = 0x0202u;

		if (d)
			(void)kgenome_emu_mem_wr(e, d, &ver, 2u);
		return 0;
	}
	case KGENOME_EMU_WIN_WSACleanup:
	case KGENOME_EMU_WIN_connect:
	case KGENOME_EMU_WIN_bind:
	case KGENOME_EMU_WIN_listen:
	case KGENOME_EMU_WIN_shutdown:
	case KGENOME_EMU_WIN_setsockopt:
	case KGENOME_EMU_WIN_ioctlsocket:
	case KGENOME_EMU_WIN_closesocket:
		return 0;
	case KGENOME_EMU_WIN_WSASocketA:
	case KGENOME_EMU_WIN_WSASocketW:
	case KGENOME_EMU_WIN_socket:
	case KGENOME_EMU_WIN_accept:
		return kgenome_emu_win_sock_new(e);
	case KGENOME_EMU_WIN_send:
	case KGENOME_EMU_WIN_sendto:
		return kgenome_emu_win_arg(e, 2) & 0xffffffffu;
	case KGENOME_EMU_WIN_recv:
	case KGENOME_EMU_WIN_recvfrom: {
		uint64_t s = kgenome_emu_win_arg(e, 0), buf = kgenome_emu_win_arg(e, 1);
		uint64_t len = kgenome_emu_win_arg(e, 2) & 0xffffffffu;

		if (len && kgenome_emu_win_sock_first_read(e, s)) {
			uint32_t sz = 0x1000u;
			unsigned m = len < 4u ? (unsigned)len : 4u;

			(void)kgenome_emu_mem_wr(e, buf, &sz, m);
			return m;
		}
		return len;
	}
	default:
		*mine = 0;
		return 0;
	}
}

/*
 * MultiByteToWideChar(CodePage, Flags, MultiByteStr, cbMultiByte, WideCharStr, cchWideChar) and
 * WideCharToMultiByte(CodePage, Flags, WideCharStr, cchWideChar, MultiByteStr, cbMultiByte, DefaultChar,
 * UsedDefaultChar), after their documentation:
 *   - a length of -1 means "up to and including the terminator" and the converted string then has one too;
 *   - an output size of 0 asks only for the size the result needs; a size too small is 0 with
 *     ERROR_INSUFFICIENT_BUFFER (122), and nothing is written;
 *   - CP_UTF8 (65001) is converted exactly (an invalid sequence is U+FFFD, or an error, 1113, under
 *     MB_ERR_INVALID_CHARS 0x8); any other page is treated as a single byte page whose 0x00-0xFF are U+0000-U+00FF
 *     (exact for ISO 8859-1, exact for the ASCII half of every ANSI page, and a stand-in for the upper half of
 *     the others: the interpreter has no code page tables), and in the other direction a character above U+00FF
 *     becomes the default character ('?') with *UsedDefaultChar set.
 * The text read is bounded at KGENOME_EMU_WIN_CONV_MAX characters: a source with no terminator cannot run the
 * conversion over the whole address space, and a request past it fails with ERROR_INSUFFICIENT_BUFFER.
 */
#define KGENOME_EMU_WIN_CONV_MAX 0x100000u

/* the characters of a source string: `n` of them read from guest memory as 1 or 2 byte units, or up to and
 * including a NUL when n is -1. Returns the count, or (uint64_t)-1 when unreadable or past the bound. */
static uint64_t conv_read(struct kgenome_emu *e, uint64_t va, int64_t n, unsigned unit, uint8_t **out)
{
	uint8_t *buf;
	uint64_t cnt = 0;

	if (n >= 0) {
		if ((uint64_t)n > KGENOME_EMU_WIN_CONV_MAX)
			return ~(uint64_t)0;
		cnt = (uint64_t)n;
	} else {
		uint64_t c = 1;

		while (cnt < KGENOME_EMU_WIN_CONV_MAX) {
			c = 0;
			if (!kgenome_emu_mem_rd(e, va + cnt * unit, &c, unit))
				return ~(uint64_t)0;
			cnt++;
			if (!c)
				break;
		}
		if (c)
			return ~(uint64_t)0;
	}
	buf = malloc(cnt * unit + 1u);
	if (!buf)
		return ~(uint64_t)0;
	{
		uint64_t done = 0;

		/* a page at a time: a faulting tail is an unreadable source, and nothing is half converted */
		while (done < cnt * unit) {
			uint64_t chunk = cnt * unit - done > 4096u ? 4096u : cnt * unit - done;

			if (!kgenome_emu_mem_rd(e, va + done, buf + done, (unsigned)chunk)) {
				free(buf);
				return ~(uint64_t)0;
			}
			done += chunk;
		}
	}
	*out = buf;
	return cnt;
}

static uint64_t conv_put(struct kgenome_emu *e, uint64_t va, const uint8_t *buf, uint64_t bytes)
{
	uint64_t done = 0;

	while (done < bytes) {
		uint64_t chunk = bytes - done > 4096u ? 4096u : bytes - done;

		if (!kgenome_emu_mem_wr(e, va + done, buf + done, (unsigned)chunk))
			return 0;
		done += chunk;
	}
	return 1;
}

static uint64_t win_mb2wc(struct kgenome_emu *e)
{
	uint64_t cp = kgenome_emu_win_arg(e, 0) & 0xffffffffu, fl = kgenome_emu_win_arg(e, 1) & 0xffffffffu;
	uint64_t src = kgenome_emu_win_arg(e, 2), dst = kgenome_emu_win_arg(e, 4);
	int64_t cb = (int32_t)kgenome_emu_win_arg(e, 3);
	uint64_t cch = kgenome_emu_win_arg(e, 5) & 0xffffffffu;
	uint8_t *in = NULL;
	uint64_t n, i, nout = 0;
	uint16_t *w = NULL;
	int utf8 = cp == 65001u, bad = 0;

	if (!src || (cb < 0 && cb != -1)) {
		e->win_last_error = 87u;                    /* ERROR_INVALID_PARAMETER */
		return 0;
	}
	n = conv_read(e, src, cb, 1u, &in);
	if (n == ~(uint64_t)0) {
		e->win_last_error = 87u;                    /* unreadable, or past the bound */
		return 0;
	}
	w = malloc((n + 1u) * 2u * sizeof *w);
	if (!w) {
		free(in);
		return 0;
	}
	for (i = 0; i < n; ) {
		uint8_t c = in[i];
		uint32_t cpv = c;
		unsigned take = 1;

		if (utf8 && c >= 0x80u) {
			static const uint32_t least[4] = { 0, 0x80u, 0x800u, 0x10000u };
			unsigned need = (c >= 0xc2u && c <= 0xdfu) ? 1u : (c >= 0xe0u && c <= 0xefu) ? 2u :
					(c >= 0xf0u && c <= 0xf4u) ? 3u : 0u;
			unsigned k = 1;
			uint32_t v = need ? (uint32_t)(c & (0x3fu >> need)) : 0u;

			while (k <= need && i + k < n && (in[i + k] & 0xc0u) == 0x80u)
				v = (v << 6) | (in[i + k++] & 0x3fu);
			take = k;                               /* the lead byte and the continuation bytes it had */
			if (need && k == need + 1u && v >= least[need] && v <= 0x10ffffu &&
			    !(v >= 0xd800u && v <= 0xdfffu)) {
				cpv = v;
			} else {
				cpv = 0xfffdu;                  /* an invalid or truncated sequence */
				bad = 1;
			}
		}
		i += take;
		if (cpv >= 0x10000u && cpv != 0xfffdu) {
			cpv -= 0x10000u;
			w[nout++] = (uint16_t)(0xd800u | (cpv >> 10));
			w[nout++] = (uint16_t)(0xdc00u | (cpv & 0x3ffu));
		} else {
			w[nout++] = (uint16_t)cpv;
		}
	}
	free(in);
	if (bad && (fl & 0x8u)) {                           /* MB_ERR_INVALID_CHARS */
		free(w);
		e->win_last_error = 1113u;                  /* ERROR_NO_UNICODE_TRANSLATION */
		return 0;
	}
	if (cch && nout > cch) {
		free(w);
		e->win_last_error = 122u;                   /* ERROR_INSUFFICIENT_BUFFER */
		return 0;
	}
	if (cch && !conv_put(e, dst, (const uint8_t *)w, nout * 2u)) {
		free(w);
		e->win_last_error = 87u;
		return 0;
	}
	free(w);
	return nout;
}

static uint64_t win_wc2mb(struct kgenome_emu *e)
{
	uint64_t cp = kgenome_emu_win_arg(e, 0) & 0xffffffffu;
	uint64_t src = kgenome_emu_win_arg(e, 2), dst = kgenome_emu_win_arg(e, 4);
	int64_t cw = (int32_t)kgenome_emu_win_arg(e, 3);
	uint64_t cb = kgenome_emu_win_arg(e, 5) & 0xffffffffu;
	uint64_t defp = kgenome_emu_win_arg(e, 6), usedp = kgenome_emu_win_arg(e, 7);
	uint8_t *in = NULL, *o;
	uint64_t n, i, nout = 0;
	uint8_t dch = '?';
	uint32_t used = 0;
	int utf8 = cp == 65001u;

	if (!src || (cw < 0 && cw != -1)) {
		e->win_last_error = 87u;
		return 0;
	}
	n = conv_read(e, src, cw, 2u, &in);
	if (n == ~(uint64_t)0) {
		e->win_last_error = 87u;
		return 0;
	}
	if (defp && !utf8) {
		uint64_t c = 0;

		if (kgenome_emu_mem_rd(e, defp, &c, 1u))
			dch = (uint8_t)c;
	}
	o = malloc(n * 4u + 4u);
	if (!o) {
		free(in);
		return 0;
	}
	for (i = 0; i < n; i++) {
		uint32_t c = kof_ld_le16(in + 2u * i);

		if (utf8) {
			if (c >= 0xd800u && c <= 0xdbffu && i + 1u < n) {
				uint32_t d = kof_ld_le16(in + 2u * (i + 1u));

				if (d >= 0xdc00u && d <= 0xdfffu) {
					c = 0x10000u + ((c - 0xd800u) << 10) + (d - 0xdc00u);
					i++;
				}
			}
			if (c >= 0xd800u && c <= 0xdfffu)
				c = 0xfffdu;                    /* a lone surrogate */
			if (c < 0x80u) {
				o[nout++] = (uint8_t)c;
			} else if (c < 0x800u) {
				o[nout++] = (uint8_t)(0xc0u | (c >> 6));
				o[nout++] = (uint8_t)(0x80u | (c & 0x3fu));
			} else if (c < 0x10000u) {
				o[nout++] = (uint8_t)(0xe0u | (c >> 12));
				o[nout++] = (uint8_t)(0x80u | ((c >> 6) & 0x3fu));
				o[nout++] = (uint8_t)(0x80u | (c & 0x3fu));
			} else {
				o[nout++] = (uint8_t)(0xf0u | (c >> 18));
				o[nout++] = (uint8_t)(0x80u | ((c >> 12) & 0x3fu));
				o[nout++] = (uint8_t)(0x80u | ((c >> 6) & 0x3fu));
				o[nout++] = (uint8_t)(0x80u | (c & 0x3fu));
			}
		} else if (c < 0x100u) {
			o[nout++] = (uint8_t)c;
		} else {
			o[nout++] = dch;
			used = 1;
		}
	}
	free(in);
	if (cb && nout > cb) {
		free(o);
		e->win_last_error = 122u;
		return 0;
	}
	if (cb && !conv_put(e, dst, o, nout)) {
		free(o);
		e->win_last_error = 87u;
		return 0;
	}
	free(o);
	if (usedp && !utf8)
		kgenome_emu_mem_wr(e, usedp, &used, 4u);
	return nout;
}

/*
 * modules and virtual memory: the loader's own questions.
 *
 * One arm of the dispatch in kgenome_emu_winapi_do, moved out so the dispatch stays readable.
 * Sets *mine to 0 for an id that is not one of its own.
 */
static uint64_t win_loader(struct kgenome_emu *e, unsigned id, int *mine)
{
	char name[128];

	*mine = 1;
	switch (id) {
	case KGENOME_EMU_WIN_GetModuleHandleA:
	case KGENOME_EMU_WIN_GetModuleHandleW: {
		uint64_t p = kgenome_emu_win_arg(e, 0);

		/*
		 * NULL means "this program", which is the image's own base -
		 * the one thing here that is definitely true. Any other name
		 * resolves to the one module this environment has.
		 */
		if (!p) {
			kgenome_emu_win_trace(e, "GetModuleHandle", "(self)",
				  e->win_image_base);
			return e->win_image_base;
		}
		kgenome_emu_win_str(e, p, name, sizeof name, id == KGENOME_EMU_WIN_GetModuleHandleW);
		{
			uint64_t h = kgenome_emu_win_mod_of(e, name);

			/* a library LoadLibrary has made a handle for is loaded from then on */
			if (!h)
				h = kgenome_emu_win_fake_find(e, name);
			kgenome_emu_win_trace(e, "GetModuleHandle", name, h);
			return h;       /* zero is "not loaded", which is true */
		}
	}
	case KGENOME_EMU_WIN_LoadLibraryA:
	case KGENOME_EMU_WIN_LoadLibraryW: {
		uint64_t p = kgenome_emu_win_arg(e, 0);

		kgenome_emu_win_str(e, p, name, sizeof name, id == KGENOME_EMU_WIN_LoadLibraryW);
		{
			uint64_t h = kgenome_emu_win_mod_of(e, name);

			if (!h)
				h = kgenome_emu_win_fake_lib(e, name);
			kgenome_emu_win_trace(e, "LoadLibrary", name, h);
			return h;
		}
	}
	case KGENOME_EMU_WIN_GetProcAddress: {
		uint64_t h = kgenome_emu_win_arg(e, 0), p = kgenome_emu_win_arg(e, 1);

		{
			unsigned mi;
			int known = 0;

			for (mi = 0; mi < KGENOME_EMU_WIN_MOD_COUNT; mi++)
				if (h && h == e->win_mod_base[mi])
					known = 1;
			if (!known && kgenome_emu_win_is_fake(e, h)) {
				uint64_t a;

				if (p >= 0x10000u) {
					kgenome_emu_win_str(e, p, name, sizeof name, 0);
					a = kgenome_emu_win_resolve(e, name);
				} else {
					/* An ordinal into a library with no image:
					 * there is no table to look it up in. */
					a = kgenome_emu_win_miss_thunk(e);
				}
				kgenome_emu_win_trace(e, "GetProcAddress", p >= 0x10000u ? name : "(by ordinal)", a);
				return a;
			}
			if (!known) {
				/* A handle this environment did not hand out.
				 * Silent until now, and a zero from here is
				 * indistinguishable from a name that is not
				 * exported - two different things to fix. */
				kgenome_emu_win_trace(e, "GetProcAddress", "(handle?)", h);
				return 0;
			}
		}
		/* An ordinal, not a name: the high bits are zero. */
		if (p < 0x10000u) {
			kgenome_emu_win_trace(e, "GetProcAddress", "(by ordinal)", p);
			return 0;
		}
		kgenome_emu_win_str(e, p, name, sizeof name, 0);
		{
			uint64_t a = kgenome_emu_win_resolve(e, name);

			kgenome_emu_win_trace(e, "GetProcAddress", name, a);
			return a;
		}
	}
	case KGENOME_EMU_WIN_VirtualAlloc: {
		uint64_t at  = kgenome_emu_win_arg(e, 0), sz = kgenome_emu_win_arg(e, 1);
		uint64_t pr  = kgenome_emu_win_arg(e, 3);
		unsigned prot = kgenome_emu_win_prot(pr);

		KOF_TRACE("[win]   VirtualAlloc(at=%#llx sz=%#llx type=%#llx prot=%#llx) rip=%#llx\n",
				(unsigned long long)at, (unsigned long long)sz,
				(unsigned long long)kgenome_emu_win_arg(e, 2),
				(unsigned long long)pr,
				(unsigned long long)e->rip);
		if (!sz)
			return 0;
		if (at) {
			/*
			 * NOT OVER A LIBRARY'S IMAGE, BECAUSE WINDOWS REFUSES.
			 *
			 * VirtualAlloc with an explicit address inside a mapped
			 * image fails there - the range is already committed as
			 * part of the section view, and MEM_RESERVE over it
			 * returns NULL. Succeeding is therefore an answer no
			 * real machine gives, and a protector that asks is
			 * usually asking precisely because of that.
			 *
			 * Measured on Themida: the loader calls
			 * VirtualAlloc(kernel32 + 0x1000, 0x1000,
			 * MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE) four
			 * times over - the page holding this environment's own
			 * export stubs - and carried on down a path whose
			 * pointers were garbage within a few thousand
			 * instructions.
			 */
			unsigned mi;

			for (mi = 0; mi < KGENOME_EMU_WIN_MOD_COUNT; mi++) {
				uint64_t mb = e->win_mod_base[mi];

				if (mb && at >= mb && at - mb < KGENOME_EMU_WIN_MOD_SPAN) {
					kgenome_emu_win_trace(e, "VirtualAlloc",
						  "(over a module image)", 0);
					return 0;
				}
			}
			/* A guest asking for a specific address usually already
			 * owns it - the Windows call succeeds on memory it has
			 * reserved. Mapping over it is what MEM_COMMIT does. */
			uint64_t base = at & ~(uint64_t)(KGENOME_EMU_PAGE - 1u);
			uint64_t len = (sz + (at - base) + KGENOME_EMU_PAGE - 1u) &
				       ~(uint64_t)(KGENOME_EMU_PAGE - 1u);

			if (!kgenome_emu_vma_add(e, base, len, 0, prot, 0))
				return 0;
			return at;
		}
		return e->bits == 32 ? kgenome_emu_win_alloc32(e, sz, prot)
				     : kgenome_emu_win_alloc(e, sz, prot);
	}
	case KGENOME_EMU_WIN_VirtualProtect: {
		uint64_t at = kgenome_emu_win_arg(e, 0), sz = kgenome_emu_win_arg(e, 1);
		uint64_t pr = kgenome_emu_win_arg(e, 2), old = kgenome_emu_win_arg(e, 3);
		uint64_t base = at & ~(uint64_t)(KGENOME_EMU_PAGE - 1u);
		uint64_t len = (sz + (at - base) + KGENOME_EMU_PAGE - 1u) &
			       ~(uint64_t)(KGENOME_EMU_PAGE - 1u);
		uint32_t four = 0x40u;

		(void)base; (void)len;
		if (!sz)
			return 0;
		/*
		 * THIS IS THE ONE THAT MATTERS TO A SCAN, and it does exactly
		 * what EMU_SYS_MPROTECT does a few cases down - takes a
		 * snapshot and reports success, without moving any permission.
		 *
		 * The snapshot is the point: a program saying "this is code
		 * now" about memory it just wrote is a payload saying so about
		 * itself, and that is what the harvest collects. Not moving the
		 * permission is the Linux side's decision and is kept here
		 * rather than diverged from - a run is short, nothing in it
		 * benefits from being denied access it asked for, and two
		 * protection models in one interpreter is how they drift.
		 */
		if (kgenome_emu_win_prot(pr) & KGENOME_EMU_X)
			kgenome_emu_snap_take(e, at, sz);
		if (old)
			kgenome_emu_mem_wr(e, old, &four, 4u);
		return 1;
	}
	case KGENOME_EMU_WIN_VirtualFree:
		/* Nothing is reclaimed: a run is short and its memory is what a
		 * harvest reads afterwards. Freeing would throw away the thing
		 * this whole interpreter exists to collect. */
		return 1;
	default:
		*mine = 0;
		return 0;
	}
}

/*
 * the process, its identity and its exception handlers.
 *
 * One arm of the dispatch in kgenome_emu_winapi_do, moved out so the dispatch stays readable.
 * Sets *mine to 0 for an id that is not one of its own.
 */
static uint64_t win_process(struct kgenome_emu *e, unsigned id, int *stop_out, int *mine)
{
	*mine = 1;
	switch (id) {
	case KGENOME_EMU_WIN_ExitProcess:
		*stop_out = KGENOME_EMU_STOP_EXIT + 1;
		return 0;
	case KGENOME_EMU_WIN_GetCurrentProcess:
		return (uint64_t)-1;            /* the pseudo handle */
	case KGENOME_EMU_WIN_IsDebuggerPresent:
		return 0;
	case KGENOME_EMU_WIN_GetLastError:
		return e->win_last_error;
	case KGENOME_EMU_WIN_SetLastError:
		e->win_last_error = (uint32_t)kgenome_emu_win_arg(e, 0);
		return 0;
	case KGENOME_EMU_WIN_GetVersion:
		/*
		 * MAJOR IS THE LOW BYTE. This returned 0x0a00, which reads as
		 * major 0, minor 10 - and a program that starts by checking
		 * `LOBYTE(LOWORD(v)) >= 5` sees major zero and takes its
		 * failure path. Measured on an MPRESS sample: it read this,
		 * carried a null pointer from there, tested it with
		 * IsBadWritePtr, and raised STATUS_FLOAT_DIVIDE_BY_ZERO with
		 * no handler registered - fourteen and a half million
		 * instructions in.
		 *
		 * 10.0 build 19045, which is what RtlGetVersion above already
		 * says; the two used to disagree.
		 */
		return (19045u << 16) | (0u << 8) | 10u;
	case KGENOME_EMU_WIN_GetCurrentProcessId:
		return 0x1000u;
	case KGENOME_EMU_WIN_AddVectoredExceptionHandler: {
		uint64_t first = kgenome_emu_win_arg(e, 0), h = kgenome_emu_win_arg(e, 1);
		unsigned i;

		if (!h || e->n_veh >= sizeof e->win_veh / sizeof e->win_veh[0])
			return 0;
		if (first) {
			/* FIRST means first CALLED, so it goes at the front and
			 * the rest move down - the order of this list is the
			 * order they are tried in. */
			for (i = e->n_veh; i > 0; i--)
				e->win_veh[i] = e->win_veh[i - 1];
			e->win_veh[0] = h;
		} else {
			e->win_veh[e->n_veh] = h;
		}
		e->n_veh++;
		/* The handle IS the handler address. Windows returns an opaque
		 * value and a guest may only pass it back to Remove, so the
		 * simplest value that round-trips is the right one. */
		return h;
	}
	case KGENOME_EMU_WIN_RemoveVectoredExceptionHandler: {
		uint64_t h = kgenome_emu_win_arg(e, 0);
		unsigned i, j;

		for (i = 0, j = 0; i < e->n_veh; i++)
			if (e->win_veh[i] != h)
				e->win_veh[j++] = e->win_veh[i];
		if (j == e->n_veh)
			return 0;
		e->n_veh = j;
		return 1;
	}
	/*
	 * A HEAP, WHICH IS ONE ARENA AND NO FREE LIST.
	 *
	 * A run is short and its memory is what the harvest reads afterwards,
	 * so reclaiming would throw away the thing this exists to collect -
	 * the same decision VirtualFree makes above. HeapAlloc therefore hands
	 * out fresh pages every time and HeapFree does nothing, which is
	 * wasteful and cannot be wrong.
	 */
	default:
		*mine = 0;
		return 0;
	}
}

/*
 * the heap, memory queries, the clock and thread-local storage.
 *
 * One arm of the dispatch in kgenome_emu_winapi_do, moved out so the dispatch stays readable.
 * Sets *mine to 0 for an id that is not one of its own.
 */
static uint64_t win_heap_time(struct kgenome_emu *e, unsigned id, int *mine)
{
	*mine = 1;
	switch (id) {
	case KGENOME_EMU_WIN_GetProcessHeap:
		return e->win_heap;
	case KGENOME_EMU_WIN_HeapAlloc:
	case KGENOME_EMU_WIN_RtlAllocateHeap: {
		uint64_t sz = kgenome_emu_win_arg(e, 2), fl = kgenome_emu_win_arg(e, 1);
		uint64_t at = e->bits == 32
			      ? kgenome_emu_win_alloc32(e, sz, KGENOME_EMU_R | KGENOME_EMU_W)
			      : kgenome_emu_win_alloc(e, sz, KGENOME_EMU_R | KGENOME_EMU_W);

		/* HEAP_ZERO_MEMORY is bit 3, and the pages are fresh, so the
		 * flag is already honoured whether it was asked for or not. */
		(void)fl;
		if (at)
			kgenome_emu_win_heap_note(e, at, sz);
		return at;
	}
	/*
	 * HeapReAlloc(heap, flags, ptr, size): a new block that holds the old contents, up to the smaller of the
	 * two sizes. The old size is the one HeapAlloc recorded (kgenome_emu_win_heap_note). A pointer this heap did
	 * not hand out is not a block it can copy from, and gets a fresh block as before. HEAP_REALLOC_IN_PLACE_ONLY
	 * (0x10) cannot be honoured by a growing block, which is NULL - the documented failure.
	 */
	case KGENOME_EMU_WIN_HeapReAlloc: {
		uint64_t fl = kgenome_emu_win_arg(e, 1), old = kgenome_emu_win_arg(e, 2);
		uint64_t sz = kgenome_emu_win_arg(e, 3), at, keep = 0;
		struct kgenome_emu_hblk *ob = kgenome_emu_win_heap_find(e, old);

		if (ob && ob->size != KGENOME_EMU_HBLK_FREED) {
			keep = ob->size < sz ? ob->size : sz;
			if ((fl & 0x10u) && sz > ob->size)
				return 0;
		}
		at = e->bits == 32 ? kgenome_emu_win_alloc32(e, sz, KGENOME_EMU_R | KGENOME_EMU_W)
				   : kgenome_emu_win_alloc(e, sz, KGENOME_EMU_R | KGENOME_EMU_W);
		if (!at)
			return 0;
		kgenome_emu_win_heap_note(e, at, sz);
		/* the block is page-granular, so a copy in page bites cannot run past either block */
		for (uint64_t done = 0; done < keep; ) {
			uint8_t page[KGENOME_EMU_PAGE];
			uint64_t chunk = keep - done > sizeof page ? sizeof page : keep - done;

			if (!kgenome_emu_mem_rd(e, old + done, page, (unsigned)chunk) ||
			    !kgenome_emu_mem_wr(e, at + done, page, (unsigned)chunk))
				break;
			done += chunk;
		}
		if (ob)
			ob->size = KGENOME_EMU_HBLK_FREED;     /* the old block is released */
		return at;
	}
	case KGENOME_EMU_WIN_HeapFree:
	case KGENOME_EMU_WIN_RtlFreeHeap: {
		struct kgenome_emu_hblk *b = kgenome_emu_win_heap_find(e, kgenome_emu_win_arg(e, 2));

		if (b)
			b->size = KGENOME_EMU_HBLK_FREED;      /* memory is never reused (see the note above) */
		return 1;
	}
	/* HeapSize: the size the block was allocated with; (SIZE_T)-1 for a pointer that is not a live block of
	 * this heap, which is what Windows answers for one it does not recognise. */
	case KGENOME_EMU_WIN_HeapSize: {
		struct kgenome_emu_hblk *b = kgenome_emu_win_heap_find(e, kgenome_emu_win_arg(e, 2));

		if (!b || b->size == KGENOME_EMU_HBLK_FREED)
			return e->bits == 32 ? 0xffffffffull : ~(uint64_t)0;
		return b->size;
	}
	case KGENOME_EMU_WIN_VirtualQuery: {
		uint64_t at = kgenome_emu_win_arg(e, 0), out = kgenome_emu_win_arg(e, 1);
		uint64_t page = at & ~(uint64_t)(KGENOME_EMU_PAGE - 1u);
		uint32_t w32;

		if (!out)
			return 0;
		/* MEMORY_BASIC_INFORMATION, the fields a stub reads: the base,
		 * the size, the state and the protection. Reported as one
		 * committed readable-writable-executable page, because that is
		 * what this interpreter's memory is - it does not model the
		 * distinctions the rest of the structure draws. */
		if (e->bits == 32) {
			w32 = (uint32_t)page;      kgenome_emu_mem_wr(e, out, &w32, 4u);
			w32 = (uint32_t)page;      kgenome_emu_mem_wr(e, out + 4u, &w32, 4u);
			w32 = 0x40u;               kgenome_emu_mem_wr(e, out + 8u, &w32, 4u);
			w32 = KGENOME_EMU_PAGE;        kgenome_emu_mem_wr(e, out + 12u, &w32, 4u);
			w32 = 0x1000u;             kgenome_emu_mem_wr(e, out + 16u, &w32, 4u);
			w32 = 0x40u;               kgenome_emu_mem_wr(e, out + 20u, &w32, 4u);
			w32 = 0x20000u;            kgenome_emu_mem_wr(e, out + 24u, &w32, 4u);
			return 28u;
		}
		kgenome_emu_mem_wr(e, out, &page, 8u);
		kgenome_emu_mem_wr(e, out + 8u, &page, 8u);
		w32 = 0x40u;                  kgenome_emu_mem_wr(e, out + 16u, &w32, 4u);
		{ uint64_t sz = KGENOME_EMU_PAGE; kgenome_emu_mem_wr(e, out + 24u, &sz, 8u); }
		w32 = 0x1000u;                kgenome_emu_mem_wr(e, out + 32u, &w32, 4u);
		w32 = 0x40u;                  kgenome_emu_mem_wr(e, out + 36u, &w32, 4u);
		w32 = 0x20000u;               kgenome_emu_mem_wr(e, out + 40u, &w32, 4u);
		return 48u;
	}
	case KGENOME_EMU_WIN_GetSystemInfo: {
		uint64_t out = kgenome_emu_win_arg(e, 0);
		uint32_t w32;

		if (!out)
			return 0;
		w32 = 9u;          kgenome_emu_mem_wr(e, out, &w32, 4u);        /* AMD64/INTEL */
		w32 = KGENOME_EMU_PAGE; kgenome_emu_mem_wr(e, out + 4u, &w32, 4u);  /* page size */
		w32 = 1u;          kgenome_emu_mem_wr(e, out + (e->bits == 32 ? 20u : 32u),
					  &w32, 4u);               /* one CPU */
		return 0;
	}
	case KGENOME_EMU_WIN_Sleep:
		/* See the Linux side's note on sleeping: it is the cheapest
		 * anti-emulation trick there is, and the answer is to return
		 * at once rather than to refuse. */
		return 0;
	case KGENOME_EMU_WIN_QueryPerformanceCounter: {
		uint64_t out = kgenome_emu_win_arg(e, 0);
		uint64_t v = e->insn;      /* monotonic, and it is the clock */

		if (out)
			kgenome_emu_mem_wr(e, out, &v, 8u);
		return 1;
	}
	case KGENOME_EMU_WIN_QueryPerformanceFrequency: {
		uint64_t out = kgenome_emu_win_arg(e, 0);
		uint64_t v = 1000000ull;

		if (out)
			kgenome_emu_mem_wr(e, out, &v, 8u);
		return 1;
	}
	case KGENOME_EMU_WIN_GetSystemTimeAsFileTime: {
		uint64_t out = kgenome_emu_win_arg(e, 0);
		/* A fixed date plus the instruction count, so it is plausible,
		 * monotonic, and the same on every run of the same file. */
		uint64_t v = 0x01d80000ull * 0x100000000ull + e->insn;

		if (out)
			kgenome_emu_mem_wr(e, out, &v, 8u);
		return 0;
	}
	case KGENOME_EMU_WIN_GetCurrentThreadId:
		return 0x2000u;
	case KGENOME_EMU_WIN_GetCurrentThread:
		return (uint64_t)-2;            /* the pseudo handle */
	case KGENOME_EMU_WIN_TlsAlloc:
		return e->win_tls_next < 64u ? e->win_tls_next++
					     : (uint64_t)-1;
	case KGENOME_EMU_WIN_TlsGetValue: {
		uint64_t i = kgenome_emu_win_arg(e, 0);

		return i < 64u ? e->win_tls[i] : 0;
	}
	case KGENOME_EMU_WIN_TlsSetValue: {
		uint64_t i = kgenome_emu_win_arg(e, 0);

		if (i < 64u)
			e->win_tls[i] = kgenome_emu_win_arg(e, 1);
		return 1;
	}
	case KGENOME_EMU_WIN_TlsFree:
		return 1;
	default:
		*mine = 0;
		return 0;
	}
}

/*
 * locks, handles, the module file name, the command line.
 *
 * One arm of the dispatch in kgenome_emu_winapi_do, moved out so the dispatch stays readable.
 * Sets *mine to 0 for an id that is not one of its own.
 */
static uint64_t win_handles(struct kgenome_emu *e, unsigned id, int *mine)
{
	*mine = 1;
	switch (id) {
	case KGENOME_EMU_WIN_InitializeCriticalSection:
	case KGENOME_EMU_WIN_EnterCriticalSection:
	case KGENOME_EMU_WIN_LeaveCriticalSection:
	case KGENOME_EMU_WIN_DeleteCriticalSection:
		/* One thread, so a lock is never contended and a critical
		 * section is a structure nobody has to read. */
		return 1;
	case KGENOME_EMU_WIN_FlushInstructionCache:
		return 1;
	case KGENOME_EMU_WIN_GetStdHandle:
		return 0x10u;                   /* a handle, and a distinct one */
	case KGENOME_EMU_WIN_CloseHandle:
		return 1;
	case KGENOME_EMU_WIN_SetUnhandledExceptionFilter: {
		uint64_t old = e->win_top_filter;

		e->win_top_filter = kgenome_emu_win_arg(e, 0);
		return old;
	}
	case KGENOME_EMU_WIN_GetModuleFileNameA:
	case KGENOME_EMU_WIN_GetModuleFileNameW: {
		uint64_t out = kgenome_emu_win_arg(e, 1), cap = kgenome_emu_win_arg(e, 2);
		static const char path[] = "C:\\Windows\\System32\\image.exe";
		unsigned i, len = (unsigned)sizeof path - 1u;
		int wide = id == KGENOME_EMU_WIN_GetModuleFileNameW;

		if (!out || !cap)
			return 0;
		if (len + 1u > cap)
			len = (unsigned)cap - 1u;
		for (i = 0; i <= len; i++) {
			uint32_t c = i < len ? (uint8_t)path[i] : 0u;

			kgenome_emu_mem_wr(e, out + (wide ? 2u * i : i), &c, wide ? 2u : 1u);
		}
		return len;
	}
	case KGENOME_EMU_WIN_GetCommandLineA:
	case KGENOME_EMU_WIN_GetCommandLineW: {
		/*
		 * A REAL POINTER, BECAUSE THE CALLER DEREFERENCES IT.
		 *
		 * This used to return 0 on the argument that a caller
		 * following a null pointer is the visible failure. It is
		 * visible, and it is also where two samples ended: measured,
		 * an MPRESS one reached `cmp byte ptr [rdi], 0x22` with rdi
		 * zero at 13317906 instructions - the CRT looking for the
		 * quote around argv[0]. Nothing about the run was wrong except
		 * this answer.
		 *
		 * The string is the one GetModuleFileName already invents,
		 * quoted the way Windows quotes it, so the two answers agree
		 * with each other. Allocated once per run and kept, which is
		 * what a caller holding the pointer needs; asking twice gets
		 * the same address, as it does on Windows.
		 */
		static const char cl[] = "\"C:\\Windows\\System32\\image.exe\"";
		int wide = id == KGENOME_EMU_WIN_GetCommandLineW;
		unsigned len = (unsigned)sizeof cl - 1u, i;
		uint64_t at = e->cmdline[wide];

		if (at)
			return at;
		at = e->bits == 32 ? kgenome_emu_win_alloc32(e, KGENOME_EMU_PAGE,
						 KGENOME_EMU_R | KGENOME_EMU_W)
				   : kgenome_emu_win_alloc(e, KGENOME_EMU_PAGE,
					       KGENOME_EMU_R | KGENOME_EMU_W);
		if (!at)
			return 0;
		for (i = 0; i <= len; i++) {
			uint32_t c = i < len ? (uint8_t)cl[i] : 0u;

			kgenome_emu_mem_wr(e, at + (wide ? 2u * i : i), &c, wide ? 2u : 1u);
		}
		e->cmdline[wide] = at;
		return at;
	}
	case KGENOME_EMU_WIN_lstrlenA: {
		uint64_t p = kgenome_emu_win_arg(e, 0), i = 0, c = 0;

		while (i < 0x10000u && kgenome_emu_mem_rd(e, p + i, &c, 1u) && c)
			i++;
		return i;
	}
	case KGENOME_EMU_WIN_RtlAddFunctionTable:
		return 1;
	case KGENOME_EMU_WIN_NtQueryInformationProcess:
		/*
		 * Every class is refused with STATUS_INVALID_INFO_CLASS rather
		 * than answered. Two of the classes a protector asks for -
		 * ProcessDebugPort and ProcessDebugObjectHandle - are debugger
		 * checks, and the honest answer to those is "no debugger",
		 * which is what a failed query leaves the caller's buffer
		 * saying: untouched, and it was zeroed before the call.
		 */
		return 0xc0000003ull;
	/*
	 * THE SECOND BATCH: what a protector reaches for once it has kernel32
	 * and has started work.
	 *
	 * Each one answers the least eventful thing that is true of this
	 * machine, which is the same rule the Linux side states for the
	 * services a runtime demands. Where the truthful answer is "that did
	 * not happen" - a file opened, a thread started - it is a failure and
	 * not a plausible handle, for the reason LoadLibrary refuses a library
	 * it has no image for: a handle nothing backs is taken, used, and
	 * followed into memory that was never there.
	 */
	default:
		*mine = 0;
		return 0;
	}
}

/*
 * the second batch: strings, files, threads, raising an exception.
 *
 * One arm of the dispatch in kgenome_emu_winapi_do, moved out so the dispatch stays readable.
 * Sets *mine to 0 for an id that is not one of its own.
 */
static uint64_t win_second(struct kgenome_emu *e, unsigned id, int *stop_out, int *mine)
{
	*mine = 1;
	switch (id) {
	case KGENOME_EMU_WIN_FreeLibrary:
		return 1;
	case KGENOME_EMU_WIN_LocalAlloc:
	case KGENOME_EMU_WIN_GlobalAlloc: {
		uint64_t sz = kgenome_emu_win_arg(e, 1);

		return e->bits == 32 ? kgenome_emu_win_alloc32(e, sz, KGENOME_EMU_R | KGENOME_EMU_W)
				     : kgenome_emu_win_alloc(e, sz, KGENOME_EMU_R | KGENOME_EMU_W);
	}
	case KGENOME_EMU_WIN_LocalFree:
	case KGENOME_EMU_WIN_GlobalFree:
		return 0;               /* NULL is success for both */
	case KGENOME_EMU_WIN_lstrcmpA:
	case KGENOME_EMU_WIN_lstrcmpiA: {
		uint64_t a = kgenome_emu_win_arg(e, 0), b = kgenome_emu_win_arg(e, 1), i = 0;

		for (; i < 0x10000u; i++) {
			uint64_t x = 0, y = 0;

			if (!kgenome_emu_mem_rd(e, a + i, &x, 1u) ||
			    !kgenome_emu_mem_rd(e, b + i, &y, 1u))
				return 0;
			if (id == KGENOME_EMU_WIN_lstrcmpiA) {
				if (x >= 'A' && x <= 'Z') x += 32u;
				if (y >= 'A' && y <= 'Z') y += 32u;
			}
			if (x != y)
				return x < y ? (uint64_t)-1 : 1u;
			if (!x)
				return 0;
		}
		return 0;
	}
	case KGENOME_EMU_WIN_lstrcpyA:
	case KGENOME_EMU_WIN_lstrcatA: {
		uint64_t d = kgenome_emu_win_arg(e, 0), sp = kgenome_emu_win_arg(e, 1), i = 0, c = 0;

		if (id == KGENOME_EMU_WIN_lstrcatA)
			while (i < 0x10000u && kgenome_emu_mem_rd(e, d + i, &c, 1u) && c)
				i++;
		{
			uint64_t k = 0;

			do {
				if (!kgenome_emu_mem_rd(e, sp + k, &c, 1u))
					return 0;
				if (!kgenome_emu_mem_wr(e, d + i + k, &c, 1u))
					return 0;
				k++;
			} while (c && k < 0x10000u);
		}
		return d;
	}
	case KGENOME_EMU_WIN_lstrlenW: {
		uint64_t p = kgenome_emu_win_arg(e, 0), i = 0, c = 0;

		while (i < 0x10000u && kgenome_emu_mem_rd(e, p + 2u * i, &c, 2u) && c)
			i++;
		return i;
	}
	case KGENOME_EMU_WIN_MultiByteToWideChar:
		return win_mb2wc(e);
	case KGENOME_EMU_WIN_WideCharToMultiByte:
		return win_wc2mb(e);
	case KGENOME_EMU_WIN_OutputDebugStringA:
		return 0;
	case KGENOME_EMU_WIN_SetErrorMode:
		return 0;
	case KGENOME_EMU_WIN_GetStartupInfoA:
	case KGENOME_EMU_WIN_GetStartupInfoW: {
		uint64_t out = kgenome_emu_win_arg(e, 0);
		uint32_t cb = e->bits == 32 ? 68u : 104u;

		/* Only cb, which is the field a caller checks. The rest was
		 * zeroed by whoever allocated it and zero is what a process
		 * started with no console or redirection has. */
		if (out)
			kgenome_emu_mem_wr(e, out, &cb, 4u);
		return 0;
	}
	case KGENOME_EMU_WIN_GetSystemDirectoryA:
	case KGENOME_EMU_WIN_GetWindowsDirectoryA:
	case KGENOME_EMU_WIN_GetTempPathA: {
		uint64_t out = kgenome_emu_win_arg(e, id == KGENOME_EMU_WIN_GetTempPathA ? 1u : 0u);
		uint64_t cap = kgenome_emu_win_arg(e, id == KGENOME_EMU_WIN_GetTempPathA ? 0u : 1u);
		static const char sys[]  = "C:\\Windows\\System32";
		static const char win[]  = "C:\\Windows";
		static const char tmp[]  = "C:\\Windows\\Temp\\";
		const char *p = id == KGENOME_EMU_WIN_GetSystemDirectoryA ? sys
			      : id == KGENOME_EMU_WIN_GetWindowsDirectoryA ? win : tmp;
		unsigned i, len = 0;

		while (p[len])
			len++;
		if (!out || cap <= len)
			return len + 1u;
		for (i = 0; i <= len; i++) {
			uint32_t c = (uint8_t)p[i];

			kgenome_emu_mem_wr(e, out + i, &c, 1u);
		}
		return len;
	}
	case KGENOME_EMU_WIN_GetFileAttributesA:
		return (uint64_t)-1;            /* INVALID_FILE_ATTRIBUTES */
	case KGENOME_EMU_WIN_CreateFileA:
		return (uint64_t)-1;            /* INVALID_HANDLE_VALUE */
	case KGENOME_EMU_WIN_ReadFile:
	case KGENOME_EMU_WIN_WriteFile:
	case KGENOME_EMU_WIN_SetFilePointer:
		return 0;
	case KGENOME_EMU_WIN_GetFileSize:
		return (uint64_t)-1;
	case KGENOME_EMU_WIN_CreateThread:
		/*
		 * NO THREAD, AND SAID SO. There is one instruction pointer
		 * here, so a thread reported as started is a thread that will
		 * never run - and the Linux side has the measurement for what
		 * that costs: a runtime handed a slot to a thread clone had
		 * reported starting, and then waited on it forever.
		 */
		return 0;
	case KGENOME_EMU_WIN_ResumeThread:
		return (uint64_t)-1;
	case KGENOME_EMU_WIN_WaitForSingleObject:
		return 0;                       /* WAIT_OBJECT_0 */
	case KGENOME_EMU_WIN_TerminateProcess:
		*stop_out = KGENOME_EMU_STOP_EXIT + 1;
		return 1;
	case KGENOME_EMU_WIN_RaiseException:
		/*
		 * A GUEST RAISING ITS OWN EXCEPTION, handed to the same
		 * dispatcher a fault is. Protectors use this deliberately -
		 * it is a control transfer their handler completes - so
		 * refusing it ends the run on the ordinary path of the code
		 * rather than on an error.
		 */
		/*
		 * THE ADDRESS TO BLAME IS THE CALLER'S, not this stub's. A
		 * 64-bit handler is found by looking an address up in the
		 * image's exception directory, and the stub lives in a
		 * fabricated kernel32 that has none - so the lookup has to be
		 * made with the return address, which is the instruction
		 * RaiseException interrupted.
		 */
		e->fault_va = kgenome_emu_win_arg(e, 0);
		memcpy(e->fault_kind, "raise", 6);
		e->exc_code = (uint32_t)kgenome_emu_win_arg(e, 0);
		{
			uint64_t back = 0;

			if (kgenome_emu_mem_rd(e, e->gpr[KGENOME_EMU_RSP], &back,
				   e->bits == 32 ? 4u : 8u))
				e->exc_rip = back;
		}
		if (kgenome_emu_win_exc_begin(e)) {
			e->exc_code = 0;
			e->exc_rip = 0;
			return 0;
		}
		e->exc_code = 0;
		e->exc_rip = 0;
		e->fault_kind[0] = 0;
		/*
		 * NOBODY TOOK IT, AND THE RUN CARRIES ON ANYWAY.
		 *
		 * On Windows an unhandled exception ends the process, and this
		 * used to end the run for the same reason. That is the wrong
		 * trade for an unpacker. What the run is FOR is the plaintext
		 * the guest writes, and a guest that raises on purpose - a
		 * licence check that failed, an anti-analysis trap, a path this
		 * environment pushed it down by answering something
		 * imperfectly - has usually not written it yet. Measured on an
		 * MPRESS sample: 0xc000008e, STATUS_FLOAT_DIVIDE_BY_ZERO, at
		 * 14.5 million instructions, with no VEH, no top level filter
		 * and no exception directory in the image - so no handler
		 * exists to find and stopping here is all this could do.
		 *
		 * Returning instead puts the guest back after the call with
		 * the exception simply not having happened, which is what a
		 * handler that returned EXCEPTION_CONTINUE_EXECUTION would
		 * have done.
		 *
		 * BOUNDED, because a guest raising forever is not producing.
		 * Past KGENOME_EMU_UNHANDLED_MAX the run ends as it used to, and the
		 * count is reported either way.
		 */
		if (e->exc_unhandled++ < KGENOME_EMU_UNHANDLED_MAX)
			return 0;
		snprintf(e->detail, sizeof e->detail,
			 "unhandled raise %#llx at rip %#llx, %u of them",
			 (unsigned long long)kgenome_emu_win_arg(e, 0),
			 (unsigned long long)e->rip, e->exc_unhandled);
		*stop_out = KGENOME_EMU_STOP_EXIT + 1;
		return 0;
	case KGENOME_EMU_WIN_UnhandledExceptionFilter:
		return 1;                       /* EXECUTE_HANDLER */
	/*
	 * THE C RUNTIME'S OWN IMPORTS.
	 *
	 * Not chosen from a list of what Windows has: measured. A resolver in
	 * an MPRESS sample walks this module's export directory and, when the
	 * name is not there, gets a zero and calls it. Recording the first
	 * letter of each key it searched for gave I, S, F and D - four full
	 * scans of eighty-one names that found nothing - and those are the
	 * letters of the CRT startup set. Each answer below is the one the real
	 * function gives when there is nothing to report, not a number picked
	 * to get past a check.
	 */
	default:
		*mine = 0;
		return 0;
	}
}

/*
 * the C runtime's own imports and the Nt layer.
 *
 * One arm of the dispatch in kgenome_emu_winapi_do, moved out so the dispatch stays readable.
 * Sets *mine to 0 for an id that is not one of its own.
 */
static uint64_t win_crt(struct kgenome_emu *e, unsigned id, int *mine)
{
	*mine = 1;
	switch (id) {
	case KGENOME_EMU_WIN_InitializeCriticalSectionAndSpinCount:
		return 1;                       /* TRUE: the section is ready */
	case KGENOME_EMU_WIN_IsProcessorFeaturePresent:
		return 0;                       /* this machine has no optional
						 * feature, which is true of it */
	case KGENOME_EMU_WIN_IsValidCodePage:
		return 1;
	case KGENOME_EMU_WIN_IsBadReadPtr:
	case KGENOME_EMU_WIN_IsBadWritePtr: {
		uint64_t p = kgenome_emu_win_arg(e, 0), n = kgenome_emu_win_arg(e, 1), c = 0;

		/* The honest answer, and this environment can give it: walk the
		 * range and say whether it is there. */
		if (!p)
			return 1;
		if (n > 0x10000u)
			n = 0x10000u;
		while (n--)
			if (!kgenome_emu_mem_rd(e, p++, &c, 1u))
				return 1;
		return 0;
	}
	case KGENOME_EMU_WIN_InterlockedExchange: {
		uint64_t p = kgenome_emu_win_arg(e, 0), v = kgenome_emu_win_arg(e, 1), old = 0;

		if (!kgenome_emu_mem_rd(e, p, &old, 4u))
			return 0;
		kgenome_emu_mem_wr(e, p, &v, 4u);
		return (uint32_t)old;
	}
	case KGENOME_EMU_WIN_InterlockedCompareExchange: {
		uint64_t p = kgenome_emu_win_arg(e, 0), nv = kgenome_emu_win_arg(e, 1);
		uint64_t cmp = kgenome_emu_win_arg(e, 2), old = 0;

		if (!kgenome_emu_mem_rd(e, p, &old, 4u))
			return 0;
		if ((uint32_t)old == (uint32_t)cmp)
			kgenome_emu_mem_wr(e, p, &nv, 4u);
		return (uint32_t)old;
	}
	case KGENOME_EMU_WIN_SetHandleCount:
		return kgenome_emu_win_arg(e, 0);           /* what it returns on NT */
	case KGENOME_EMU_WIN_SetStdHandle:
	case KGENOME_EMU_WIN_SetEnvironmentVariableA:
	case KGENOME_EMU_WIN_SetEnvironmentVariableW:
	case KGENOME_EMU_WIN_SetConsoleCtrlHandler:
	case KGENOME_EMU_WIN_FreeEnvironmentStringsA:
	case KGENOME_EMU_WIN_FreeEnvironmentStringsW:
	case KGENOME_EMU_WIN_FlushFileBuffers:
	case KGENOME_EMU_WIN_FindClose:
	case KGENOME_EMU_WIN_DeleteFileA:
	case KGENOME_EMU_WIN_DisableThreadLibraryCalls:
	case KGENOME_EMU_WIN_HeapDestroy:
		return 1;                       /* TRUE */
	case KGENOME_EMU_WIN_DecodePointer:
	case KGENOME_EMU_WIN_EncodePointer:
		/* With no process cookie these are the identity, which is what
		 * they are on a system where the cookie is zero. A guest that
		 * encodes and then decodes gets its pointer back either way,
		 * and that is the only property anything depends on. */
		return kgenome_emu_win_arg(e, 0);
	case KGENOME_EMU_WIN_HeapCreate:
		/* One heap, the one GetProcessHeap already hands out. A guest
		 * that makes its own and a guest that uses the process heap
		 * then behave the same, which is what this environment can
		 * honestly support. */
		return e->win_heap;
	case KGENOME_EMU_WIN_GetCPInfo: {
		uint64_t out = kgenome_emu_win_arg(e, 1);
		uint32_t two = 2u, zero = 0;

		/* MaxCharSize 2, DefaultChar "?", no lead byte ranges - a
		 * double byte code page with nothing special about it. */
		if (!out)
			return 0;
		kgenome_emu_mem_wr(e, out, &two, 4u);
		two = (uint32_t)'?';
		kgenome_emu_mem_wr(e, out + 4u, &two, 1u);
		kgenome_emu_mem_wr(e, out + 5u, &zero, 1u);
		kgenome_emu_mem_wr(e, out + 6u, &zero, 4u);
		return 1;
	}
	case KGENOME_EMU_WIN_GetACP:
		return 1252u;                   /* the Latin-1 code page */
	case KGENOME_EMU_WIN_GetOEMCP:
		return 437u;
	case KGENOME_EMU_WIN_IsUserAnAdmin:
		/* FALSE. An unpacker's guest is not privileged and saying so
		 * is both true here and the answer that keeps a program on its
		 * ordinary path. */
		return 0;
	case KGENOME_EMU_WIN_CoInitialize:
		return 0;                       /* S_OK */
	case KGENOME_EMU_WIN_CoUninitialize:
		return 0;
	case KGENOME_EMU_WIN_SHGetFolderPathA:
		return 0x80004005u;             /* E_FAIL: no such folder here */

	case KGENOME_EMU_WIN_InterlockedIncrement:
	case KGENOME_EMU_WIN_InterlockedDecrement: {
		uint64_t p = kgenome_emu_win_arg(e, 0), v = 0;

		if (!kgenome_emu_mem_rd(e, p, &v, 4u))
			return 0;
		v = (uint32_t)(id == KGENOME_EMU_WIN_InterlockedIncrement ? v + 1u : v - 1u);
		kgenome_emu_mem_wr(e, p, &v, 4u);
		return v;
	}
	case KGENOME_EMU_WIN_NtProtectVirtualMemory: {
		uint64_t at = 0, sz = 0;

		/* The addresses arrive by POINTER, which is what makes this
		 * different from VirtualProtect and easy to get wrong. */
		kgenome_emu_mem_rd(e, kgenome_emu_win_arg(e, 1), &at, e->bits == 32 ? 4u : 8u);
		kgenome_emu_mem_rd(e, kgenome_emu_win_arg(e, 2), &sz, e->bits == 32 ? 4u : 8u);
		if (sz && (kgenome_emu_win_prot(kgenome_emu_win_arg(e, 3)) & KGENOME_EMU_X))
			kgenome_emu_snap_take(e, at, sz);
		return 0;                       /* STATUS_SUCCESS */
	}
	case KGENOME_EMU_WIN_NtAllocateVirtualMemory: {
		uint64_t pbase = kgenome_emu_win_arg(e, 1), psz = kgenome_emu_win_arg(e, 3);
		uint64_t sz = 0, at;

		kgenome_emu_mem_rd(e, psz, &sz, e->bits == 32 ? 4u : 8u);
		at = e->bits == 32 ? kgenome_emu_win_alloc32(e, sz, KGENOME_EMU_R | KGENOME_EMU_W)
				   : kgenome_emu_win_alloc(e, sz, KGENOME_EMU_R | KGENOME_EMU_W);
		if (!at)
			return 0xc0000017ull;   /* NO_MEMORY */
		kgenome_emu_mem_wr(e, pbase, &at, e->bits == 32 ? 4u : 8u);
		return 0;
	}
	case KGENOME_EMU_WIN_RtlGetVersion: {
		uint64_t out = kgenome_emu_win_arg(e, 0);
		uint32_t v;

		if (!out)
			return 0xc000000dull;
		v = 284u; kgenome_emu_mem_wr(e, out, &v, 4u);        /* dwOSVersionInfoSize */
		v = 10u;  kgenome_emu_mem_wr(e, out + 4u, &v, 4u);   /* MajorVersion */
		v = 0u;   kgenome_emu_mem_wr(e, out + 8u, &v, 4u);   /* MinorVersion */
		v = 19045u; kgenome_emu_mem_wr(e, out + 12u, &v, 4u);/* BuildNumber */
		return 0;
	}
	case KGENOME_EMU_WIN_LdrLoadDll:
		return 0xc0000135ull;           /* DLL_NOT_FOUND */
	case KGENOME_EMU_WIN_LdrGetProcedureAddress:
		return 0xc0000139ull;           /* ENTRYPOINT_NOT_FOUND */
	case KGENOME_EMU_WIN_GetTickCount:
		/*
		 * MONOTONIC AND DERIVED FROM THE INSTRUCTION COUNT, not a
		 * constant. A stub that times a loop against a clock that
		 * never moves sees zero elapsed and can conclude it is being
		 * emulated; one that sees the clock go backwards can conclude
		 * the same. This moves forward, slowly, and only forward.
		 */
		return (e->insn >> 16) & 0xffffffffu;
	default:
		*mine = 0;
		return 0;
	}
}

uint64_t kgenome_emu_winapi_do(struct kgenome_emu *e, unsigned id, int *stop_out)
{
	*stop_out = 0;
	kgenome_emu_win_trace(e, kgenome_emu_win_api_name(id), "(call)", 0);
	{
		uint32_t k;

		for (k = 0; k < e->n_shim; k++)
			if (e->shim[k].id == id)
				return e->shim[k].ret;
	}
	{
		int mine;
		uint64_t r;

		r = win_net(e, id, &mine);
		if (mine)
			return r;
		r = win_loader(e, id, &mine);
		if (mine)
			return r;
		r = win_process(e, id, stop_out, &mine);
		if (mine)
			return r;
		r = win_heap_time(e, id, &mine);
		if (mine)
			return r;
		r = win_handles(e, id, &mine);
		if (mine)
			return r;
		r = win_second(e, id, stop_out, &mine);
		if (mine)
			return r;
		r = win_crt(e, id, &mine);
		if (mine)
			return r;
	}
	return 0;
}

/*
 * Arguments three, four and five.
 *
 * Two and below are handled where they are read - amd64's rdx and i386's edx
 * are the same register, so arg2 needs no translation at all, and the first two
 * are taken once at the top of syscall_do. These three differ and are read in
 * only a handful of places, so they get an accessor rather than three more
 * ternaries at each site.
 */
