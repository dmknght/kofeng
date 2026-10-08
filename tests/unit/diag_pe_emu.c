/*
 * diag_pe_emu - a PE that finds its own APIs: the graph the emulator's run
 * gives it.
 *
 * WHY A TEST AND NOT A CORPUS RUN. The fault this guards is silent: a stager
 * whose resolver could not find a library produced the first node and no
 * more, and a count of nodes looks fine. What has to hold is the SHAPE - the
 * socket that WSASocket returned is the descriptor of the connect and of the
 * read; the pointer VirtualAlloc returned is that read's buffer and the target
 * of the jump that ends the run - because that shape is what a verdict asks.
 *
 * THE PROGRAM IS HAND ASSEMBLED, x86 stdcall, and calls the environment's stubs
 * by address. Nothing in it resolves anything: the point of the test is the
 * environment (the ws2_32 module, the scripted peer, the call record, the last
 * branch) and the route that reads it, and the resolver half is measured on the
 * real stagers in the notes beside kof_diag_run_pe_symbol.
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "../../libkofeng/kofeng.h"
#include "../../libkofeng/kofcore/kofmod/kofsig.h"
#include "../../libkofeng/kofcore/kofmod/kofcap.h"
#include "../../libkofeng/analyzers/parsers/kofformat.h"
#include "../../libkofeng/detectors/pathogen/kofdiag.h"
#include "../../libkofeng/analyzers/parsers/binaries/disasm/nucleo.h"
#include "../../libgenome/phenotype/kofemu.h"
#include "../../libkofeng/kofcore/kofmod/kofsym.h"
#include "../../libkofeng/analyzers/parsers/binaries/pe/pe_parse.h"
#include "../../libkofeng/analyzers/parsers/binaries/pe/pe_sym.h"

static int fails;

#define CK(cond) do { \
	if (!(cond)) { \
		printf("  FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); \
		fails++; \
	} \
} while (0)

static void put64(uint8_t *b, unsigned at, uint64_t v)
{
	unsigned i;

	for (i = 0; i < 8u; i++)
		b[at + i] = (uint8_t)(v >> (8u * i));
}
static void put32(uint8_t *b, unsigned at, uint32_t v)
{
	unsigned i;

	for (i = 0; i < 4u; i++)
		b[at + i] = (uint8_t)(v >> (8u * i));
}
static void put16(uint8_t *b, unsigned at, uint16_t v)
{
	b[at] = (uint8_t)v;
	b[at + 1u] = (uint8_t)(v >> 8);
}
static unsigned char view[1u << 21];



#define TEXT_RVA   0x1000u
#define IDATA_OFF  0x100u       /* inside the one section, to keep the file small */

/* The one section holds code at the front and an import directory behind it.
 * kernel32.dll!VirtualAlloc, one thunk, FirstThunk at +0x160 and the name at
 * +0x190. `wide` selects PE32+ (8-byte thunks) or PE32 (4-byte). */
static uint64_t pe_with_import(uint8_t *b, uint64_t cap, int wide,
			       const uint8_t *code, uint64_t n, int with_import)
{
	const unsigned hdr = 0x400, fa = 0x200, o = 0x80 + 24;
	const unsigned sec = o + 0xf0;
	const unsigned id = hdr + IDATA_OFF;
	const unsigned rva_id = TEXT_RVA + IDATA_OFF;
	const unsigned w = wide ? 8u : 4u;

	memset(b, 0, (size_t)cap);
	b[0] = 'M'; b[1] = 'Z';
	put32(b, 0x3c, 0x80);
	memcpy(b + 0x80, "PE\0\0", 4);
	put16(b, 0x84, wide ? 0x8664u : 0x014cu);
	put16(b, 0x86, 1);
	put16(b, 0x94, 0xf0);
	put16(b, 0x96, 0x22);
	put16(b, o, wide ? 0x20bu : 0x10bu);
	b[o + 2] = 14;
	put32(b, o + 4, (uint32_t)n);
	put32(b, o + 16, TEXT_RVA);
	put32(b, o + 20, TEXT_RVA);
	if (wide) {
		put64(b, o + 24, 0x140000000ull);
		put32(b, o + 32, 0x1000);
		put32(b, o + 36, fa);
		put16(b, o + 40, 6);
		put16(b, o + 48, 6);
		put32(b, o + 56, 0x2000);
		put32(b, o + 60, hdr);
		put16(b, o + 68, 3);
		put32(b, o + 108, 16);
		if (with_import) {
			put32(b, o + 112 + 8, rva_id);
			put32(b, o + 112 + 12, 40);
		}
	} else {
		put32(b, o + 24, 0x1000);
		put32(b, o + 28, 0x400000);
		put32(b, o + 32, 0x1000);
		put32(b, o + 36, fa);
		put16(b, o + 40, 6);
		put16(b, o + 48, 6);
		put32(b, o + 56, 0x2000);
		put32(b, o + 60, hdr);
		put16(b, o + 68, 3);
		put32(b, o + 92, 16);
		if (with_import) {
			put32(b, o + 96 + 8, rva_id);
			put32(b, o + 96 + 12, 40);
		}
	}
	memcpy(b + sec, ".text\0\0\0", 8);
	put32(b, sec + 8, 0x1000);
	put32(b, sec + 12, TEXT_RVA);
	put32(b, sec + 16, fa);
	put32(b, sec + 20, hdr);
	put32(b, sec + 36, 0xe0000020u);        /* CODE|EXEC|READ|WRITE */
	memcpy(b + hdr, code, (size_t)n);
	if (with_import) {
		/* descriptor: OriginalFirstThunk, 0, 0, Name, FirstThunk */
		put32(b, id + 0, rva_id + 0x40);
		put32(b, id + 12, rva_id + 0x80);
		put32(b, id + 16, rva_id + 0x60);
		/* both thunk tables hold the RVA of the hint/name entry */
		put32(b, id + 0x40, rva_id + 0x90);
		put32(b, id + 0x60, rva_id + 0x90);
		(void)w;
		memcpy(b + id + 0x80, "kernel32.dll", 13);
		memcpy(b + id + 0x92, "VirtualAlloc", 13);   /* after the 2-byte hint */
	}
	return hdr + fa;
}


static struct kof_diag_scan *scan(const uint8_t *b, uint64_t n,
				  struct kof_obj_ctx *ctx, const char *what,
				  unsigned run)
{
	const struct kof_parser *pl;
	uint32_t np, i;
	kof_buf buf;

	buf.p = b;
	buf.n = n;
	memset(ctx, 0, sizeof *ctx);
	memset(view, 0, sizeof view);
	pl = kof_parser_list(&np);
	for (i = 0; i < np; i++)
		if (pl[i].sniff && pl[i].sniff(buf) &&
		    pl[i].parse && pl[i].parse(buf, view, ctx))
			return kof_diag_scan_with(ctx, b, n, run);
	printf("  FAIL %s: the engine did not parse it\n", what);
	fails++;
	return NULL;
}

/* The address of an API's stub in the environment, which is where a program
 * that found it would be calling. */
static uint32_t stub_of(const char *name)
{
	unsigned i, n = kof_emu_win_api_count();

	for (i = 0; i < n; i++)
		if (!strcmp(kof_emu_win_api_name(i), name))
			return (uint32_t)(kof_emu_win_mod_base(kof_emu_win_api_mod(i), 32) +
					  KOF_EMU_WIN_STUB_RVA +
					  (uint64_t)kof_emu_win_api_slot(i) * KOF_EMU_WIN_STUB);
	return 0;
}

static uint8_t *emit(uint8_t *p, const uint8_t *q, unsigned n)
{
	memcpy(p, q, n);
	return p + n;
}

static uint8_t *push_imm(uint8_t *p, uint32_t v)
{
	*p++ = 0x68;
	put32(p, 0, v);
	return p + 4;
}

static uint8_t *call_stub(uint8_t *p, const char *name)
{
	*p++ = 0xb8;                    /* mov eax, stub */
	put32(p, 0, stub_of(name));
	p += 4;
	*p++ = 0xff;
	*p++ = 0xd0;                    /* call eax */
	return p;
}

static const struct kof_diag_hit *find(struct kof_diag_scan *s, uint16_t cap,
				       uint32_t *idx, uint32_t from)
{
	uint32_t i;

	for (i = from; s && i < kof_diag_scan_count(s); i++) {
		const struct kof_diag_hit *h = kof_diag_scan_at(s, i);

		if (h->cap == cap) {
			*idx = i;
			return h;
		}
	}
	return NULL;
}

static int linked(const struct kof_diag_hit *h, uint32_t from, uint8_t role)
{
	unsigned k;

	for (k = 0; k < h->n_in; k++)
		if (h->in[k].from == from && h->in[k].role == role)
			return 1;
	return 0;
}

/* What the engine said the NORMALISED VIEW's symbols are - see kof_result.syms. */
struct seen_syms {
	const uint8_t *blk;
	uint32_t       n;
	uint8_t        copy[KOF_SYM_MAX_BYTES];
	int            views;
	int            convicted;       /* findings naming Meterp on any object */
};

static int on_object(const char *name, const void *bytes, uint64_t len,
		     const struct kof_result *res, void *user)
{
	struct seen_syms *k = user;

	(void)bytes;
	(void)len;
	{
		uint32_t f;

		for (f = 0; f < res->n; f++)
			if (strstr(res->v[f].name, "Meterp"))
				k->convicted++;
	}
	if (strstr(name, ":norm") && res->syms && res->n_syms &&
	    res->n_syms <= sizeof k->copy) {
		memcpy(k->copy, res->syms, res->n_syms);
		k->blk = k->copy;
		k->n = res->n_syms;
		k->views++;
	}
	return 0;
}

static int has_sym(const struct seen_syms *k, const char *want)
{
	uint32_t i, c = kof_sym_count(k->blk, k->n);

	for (i = 0; k->blk && i < c; i++) {
		const uint8_t *r = kof_sym_rec(k->blk, k->n, i);

		if (r && !strcmp((const char *)r + KOF_SYM_R_NAME, want))
			return 1;
	}
	return 0;
}

int main(int argc, char **argv)
{
	static uint8_t b[0x1000], code[0x200];
	/* the PEB pointer, then the loader data through it: the shape of a program
	 * that means to walk the module list, which is what the run is gated on - a
	 * bare read of the PEB (the image base, BeingDebugged) is not enough */
	static const uint8_t peb[] = { 0x64, 0x8b, 0x15, 0x30, 0, 0, 0,       /* mov edx,fs:[0x30] */
				       0x8b, 0x52, 0x0c };                   /* mov edx,[edx+0xc] */
	static const uint8_t mov_esi_eax[] = { 0x89, 0xc6 };
	static const uint8_t mov_ebx_eax[] = { 0x89, 0xc3 };
	static const uint8_t push_esi[] = { 0x56 };
	static const uint8_t push_ebx[] = { 0x53 };
	/* the four bytes the first read writes go to the stack, as a stager's do:
	 * a buffer in the code page would be a write to a page about to run, which
	 * the emulator rightly takes for a handover */
	static const uint8_t room[] = { 0x83, 0xec, 0x10, 0x89, 0xe7 };  /* sub esp,16 ; mov edi,esp */
	static const uint8_t push_edi[] = { 0x57 };
	static const uint8_t jmp_ebx[] = { 0xff, 0xe3 };
	struct kof_obj_ctx ctx;
	struct kof_diag_scan *s;
	const struct kof_diag_hit *open, *conn, *rd1, *alloc, *rd2, *jump;
	uint32_t i_open = 0, i_conn = 0, i_rd1 = 0, i_alloc = 0, i_rd2 = 0, i_jmp = 0;
	uint8_t *p = code;
	uint64_t n;

	CK(stub_of("socket") != 0 && stub_of("VirtualAlloc") != 0);

	p = emit(p, peb, sizeof peb);                     /* the loader data is read */
	/* s = socket(AF_INET, SOCK_STREAM, 0) */
	p = push_imm(p, 0); p = push_imm(p, 1); p = push_imm(p, 2);
	p = call_stub(p, "socket");
	p = emit(p, mov_esi_eax, sizeof mov_esi_eax);
	/* connect(s, name, 16) */
	p = push_imm(p, 16); p = push_imm(p, 0x401300u);
	p = emit(p, push_esi, 1);
	p = call_stub(p, "connect");
	/* recv(s, scratch, 4, 0): the length */
	p = emit(p, room, sizeof room);
	p = push_imm(p, 0); p = push_imm(p, 4); p = emit(p, push_edi, 1);
	p = emit(p, push_esi, 1);
	p = call_stub(p, "recv");
	/*
	 * EVERYTHING AFTER THE LENGTH IS READ IS GATED ON THE READ HAVING
	 * ANSWERED, as a stager's is (`cmp eax,0 ; jle fail`). The scripted peer's
	 * contract is part of what is tested: a recv that returned nothing would
	 * send the program to its failure path and none of the nodes below would
	 * exist.
	 */
	{
		static const uint8_t test_eax[] = { 0x85, 0xc0 };      /* test eax,eax */
		static const uint8_t ret1[] = { 0xc3 };
		uint8_t tail[128], *q = tail;

		/* buf = VirtualAlloc(0, 0x1000, MEM_COMMIT, PAGE_EXECUTE_READWRITE) */
		q = push_imm(q, 0x40); q = push_imm(q, 0x1000); q = push_imm(q, 0x1000);
		q = push_imm(q, 0);
		q = call_stub(q, "VirtualAlloc");
		q = emit(q, mov_ebx_eax, sizeof mov_ebx_eax);
		/* recv(s, buf, 0x1000, 0): the stage */
		q = push_imm(q, 0); q = push_imm(q, 0x1000);
		q = emit(q, push_ebx, 1);
		q = emit(q, push_esi, 1);
		q = call_stub(q, "recv");
		q = emit(q, jmp_ebx, sizeof jmp_ebx);             /* and into it */
		CK((size_t)(q - tail) < 0x70u);
		p = emit(p, test_eax, sizeof test_eax);
		*p++ = 0x7e;                                      /* jle past the rest */
		*p++ = (uint8_t)(q - tail);
		p = emit(p, tail, (unsigned)(q - tail));
		p = emit(p, ret1, 1);
	}
	n = pe_with_import(b, sizeof b, 0, code, (uint64_t)(p - code), 0);
	s = scan(b, n, &ctx, "emulated stager", KOF_DIAG_RUN_APIHASH);

	open  = find(s, KOF_NUCLEO_NET_OPEN, &i_open, 0);
	conn  = find(s, KOF_NUCLEO_NET_CONNECT, &i_conn, 0);
	rd1   = find(s, KOF_NUCLEO_NET_READ, &i_rd1, 0);
	alloc = find(s, KOF_NUCLEO_ALLOC_EXEC, &i_alloc, 0);
	rd2   = rd1 ? find(s, KOF_NUCLEO_NET_READ, &i_rd2, i_rd1 + 1u) : NULL;
	jump  = find(s, KOF_NUCLEO_EXEC_REG, &i_jmp, 0);

	{ uint32_t i_peb = 0;

		CK(find(s, KOF_NUCLEO_SELF_RESOLVE, &i_peb, 0) != NULL); }   /* the gate: the read is a node */
	CK(open && conn && rd1 && alloc && rd2 && jump);
	if (!(open && conn && rd1 && alloc && rd2 && jump)) {
		uint32_t q;

		/* say what WAS found, because "a node is missing" is not a lead */
		for (q = 0; s && q < kof_diag_scan_count(s); q++)
			printf("    node %u: %s at %#llx\n", q,
			       kof_flow_cap_name(kof_diag_scan_at(s, q)->cap),
			       (unsigned long long)kof_diag_scan_at(s, q)->at);
	}
	if (open && conn && rd1 && alloc && rd2 && jump) {
		/* the socket is the descriptor of the connect and of both reads */
		CK(linked(conn, i_open, KOF_DIAG_ROLE_FD));
		CK(linked(rd1, i_open, KOF_DIAG_ROLE_FD));
		CK(linked(rd2, i_open, KOF_DIAG_ROLE_FD));
		/* the allocation is the SECOND read's buffer and not the first's */
		CK(linked(rd2, i_alloc, KOF_DIAG_ROLE_BUFFER));
		CK(!linked(rd1, i_alloc, KOF_DIAG_ROLE_BUFFER));
		/* PAGE_EXECUTE_READWRITE is W+X, which is a different statement from X */
		CK(alloc->flags & KOF_FLOWF_WX);
		/* and the run ends by jumping into it */
		CK(linked(jump, i_alloc, KOF_DIAG_ROLE_TARGET));
	}
	kof_diag_scan_free(s);

	/*
	 * THE ROUTES ARE SEPARATE. The import walk alone must not run the
	 * program, so a database that asked for it and not for the analysis
	 * pays no emulation - and has no node the analysis would have made.
	 */
	s = scan(b, n, &ctx, "import walk only", KOF_DIAG_RUN_SYMBOL);
	if (s) {
		uint32_t z;

		CK(!find(s, KOF_NUCLEO_NET_CONNECT, &z, 0));
		CK(!find(s, KOF_NUCLEO_EXEC_REG, &z, 0));
		kof_diag_scan_free(s);
	}

	/*
	 * A BYTE THAT IS NOT AN INSTRUCTION BOUNDARY is not a read of the PEB. The
	 * 0x64 of `jne +0x64` starts a decode - `mov eax, fs:[ecx+0x30]` - that
	 * is a read of the PEB pointer and was found in 57 of 300 real PE; and a read of
	 * the PEB that is not followed by a load of PEB.Ldr is every C runtime. Neither
	 * is a loader walk, and no run is made.
	 */
	{
		/* mov eax, fs:[0x30] ; ret - a REAL read of the PEB that goes
		 * nowhere (the shape of a C runtime's), then the misaligned
		 * `jne +0x64 / mov eax, fs:[ecx+0x30]` bytes. */
		static const uint8_t mis[] = { 0x64, 0xa1, 0x30, 0x00, 0x00, 0x00,
					       0xc3,
					       0x75, 0x64, 0x8b, 0x41, 0x30,
					       0xc3 };
		uint8_t bm[8192];
		uint64_t nm = pe_with_import(bm, sizeof bm, 0, mis, sizeof mis, 0);
		struct kof_obj_ctx cm;
		struct kof_diag_scan *sm = scan(bm, nm, &cm, "misaligned override",
						KOF_DIAG_RUN_APIHASH);
		struct kof_apihash *am = kof_apihash_run(&cm, bm, nm);
		uint32_t z;

		CK(am && am->n_ldr == 0u && am->n_call == 0u);
		CK(sm && !find(sm, KOF_NUCLEO_SELF_RESOLVE, &z, 0));
		kof_apihash_free(am);
		kof_diag_scan_free(sm);
	}

	/*
	 * THE SAME PRODUCT SERVES THE SYMBOLS: the names the program resolved
	 * become imports of its symbol block, once each, among the imports and
	 * ahead of the exports.
	 */
	{
		struct kof_apihash *a = kof_apihash_run(&ctx, b, n);
		static uint8_t blk[KOF_SYM_MAX_BYTES];
		kof_buf fb;
		uint32_t len, cnt, r, first_def = 0xffffffffu, last_imp = 0;
		int have_connect = 0, once = 0;

		CK(a != NULL);
		if (a) {
			CK(a->n_ldr > 0u && a->n_call > 0u);
			fb.p = b;
			fb.n = n;
			len = kof_pe_syms(fb, kof_pe(&ctx), blk, sizeof blk);
			len = kof_apihash_syms(a, blk, len, sizeof blk);
			cnt = kof_sym_count(blk, len);
			for (r = 0; r < cnt; r++) {
				const uint8_t *rec = kof_sym_rec(blk, len, r);

				if (!rec)
					continue;
				if (rec[KOF_SYM_R_FLAGS] & KOF_SYM_F_UNDEFINED)
					last_imp = r;
				else if (first_def == 0xffffffffu)
					first_def = r;
				if (!strcmp((const char *)rec + KOF_SYM_R_NAME,
					    "ws2_32.dll!connect"))
					have_connect++;
				if (!strncmp((const char *)rec + KOF_SYM_R_NAME,
					     "kernel32.dll!VirtualAlloc", 25))
					once++;
			}
			CK(have_connect == 1);
			/* imported AND resolved, and listed once */
			CK(once == 1);
			CK(first_def == 0xffffffffu || last_imp < first_def);
			CK(blk[KOF_SYM_H_ORIGIN] == KOF_SYM_ORIGIN_PE_RESOLVED);
			/* A block that already holds an EXPORT: the new import goes
			 * ahead of it, and the export is still there after. */
			{
				static uint8_t b2[KOF_SYM_MAX_BYTES];
				kof_buf none = { NULL, 0 };
				uint32_t l2 = kof_pe_syms(none, NULL, b2, sizeof b2);
				const uint8_t *r0, *r1;

				memset(b2 + l2, 0, KOF_SYM_RECLEN);
				b2[l2 + KOF_SYM_R_FLAGS] = KOF_SYM_F_DEFINED;
				memcpy(b2 + l2 + KOF_SYM_R_NAME, "an_export", 10);
				b2[KOF_SYM_H_COUNT] = 1;
				l2 += KOF_SYM_RECLEN;
				l2 = kof_apihash_syms(a, b2, l2, sizeof b2);
				CK(kof_sym_count(b2, l2) >= 2u);
				r0 = kof_sym_rec(b2, l2, 0);
				r1 = kof_sym_rec(b2, l2, kof_sym_count(b2, l2) - 1u);
				CK(r0 && (r0[KOF_SYM_R_FLAGS] & KOF_SYM_F_UNDEFINED));
				CK(r1 && !strcmp((const char *)r1 + KOF_SYM_R_NAME,
						 "an_export"));
			}
			/* a second application changes nothing */
			CK(kof_apihash_syms(a, blk, len, sizeof blk) == len);
			kof_apihash_free(a);
		}
	}


	/*
	 * ---- THROUGH THE SCANNER: the normalised view carries the names ----
	 *
	 * The same stager with a data section holding a wide string, which is
	 * what makes the normaliser rewrite something and hand over a view. The
	 * view's headers describe the file before the transform, so its symbols
	 * are not rebuildable from it and are DECLARED by the engine - and for a
	 * stager the directory lists nothing the program calls. With the PE
	 * diagnose in the database, the view says what the resolver found; with
	 * a database that lacks it - kof_scan_apihash_serving answers NULL - the
	 * view says what the directory says and nothing more.
	 */
	{
		const char *db = argc > 1 ? argv[1] : "build/release/databases";
		static uint8_t b2[0x2000];
		const unsigned o = 0x80 + 24, sec2 = o + 0xf0 + 40;
		static struct seen_syms seen;
		struct kof_scan_option opt;
		struct kof_engine *eng = keng_open(db);
		struct kof_scanner *sc = eng ? kscan_new(eng) : NULL;
		unsigned i;

		memcpy(b2, b, n);
		put16(b2, 0x86, 2);                          /* two sections */

		put32(b2, o + 56, 0x3000);                   /* SizeOfImage  */
		memcpy(b2 + sec2, ".data\0\0\0", 8);
		put32(b2, sec2 + 8, 0x1000);
		put32(b2, sec2 + 12, 0x2000);
		/* mostly zeros: a run the normaliser collapses is what makes it
		 * hand over a view at all */
		put32(b2, sec2 + 16, 0x1000);
		put32(b2, sec2 + 20, 0x600);
		put32(b2, sec2 + 36, 0xc0000040u);           /* INITIALISED|READ|WRITE */
		for (i = 0; i < 0x80; i++)
			b2[0x600 + 2u * i] = (uint8_t)('A' + i % 26u);
		CK(sc != NULL);
		if (sc) {
			memset(&opt, 0, sizeof opt);
			opt.heur_level = 2;
			/* the stager IS convicted by the graph verdict, and an object the
			 * scan stopped at is not normalised; this asks about the view */
			opt.all_matches = 1;
			{
				/* a scan needs a path to give a view its name */
				FILE *tf = fopen("build/test/pe_serves.tmp", "wb");

				CK(tf != NULL);
				if (tf) {
					fwrite(b2, 1, 0x1600, tf);
					fclose(tf);
					kscan_path(sc, "build/test/pe_serves.tmp", &opt,
						   on_object, &seen);
					remove("build/test/pe_serves.tmp");
				}
			}
			/* THE VERDICT: the stager is read off the graph - the byte
			 * rules for PE x86 and x64 are gone, and the synthetic code
			 * contains no byte any other rule knows. */
			CK(seen.convicted >= 1);
			CK(seen.views >= 1);
			CK(has_sym(&seen, "ws2_32.dll!connect"));
			CK(has_sym(&seen, "kernel32.dll!VirtualAlloc"));
			kscan_free(sc);
		}
		if (eng)
			keng_close(eng);
	}

	printf("diag pe emu: the loader read, socket/connect/read, the W+X buffer and the jump into it%s\n",
	       fails ? " - FAILED" : " - ok");
	return fails != 0;
}
