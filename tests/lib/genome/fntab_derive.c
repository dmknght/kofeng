/*
 * fntab_derive.c - PHASE 2 OF THE METADATA PARTITION (phenotype/fntab_derive.c): functions of trust DERIVED in code no metadata declares, by recursive descent
 * from the declared starts in it. Every object is BUILT here (audit_pmeta_kit.h) from bytes that reproduce one shape; no malware is embedded.
 *
 * WHAT IT PINS
 *   noret     x86-64 and i386: entry `call f; call g; <garbage>` with g unable to return: the garbage is in no derived function and no unit starts at the
 *             fake call target it would spell; entry, f and g are DERIVED (entry: ENTRY|DERIVED_SEED, f and g: DERIVED_CALL); the rest is NONE
 *   tail      a jump to another entry is a tail call (not body); a jump to a place no call names is body, a further range when only padding separates it;
 *             across another function or exact code it starts a function (DERIVED_JUMP, PM5-D1) unless a conditional branch of the body also reaches it
 *   trap      (2026-11-17, PM5-D2) the trap behind a call that does not return (ud2, hlt, int3) is the caller's; a nop there is not
 *   hole      (2026-11-17, FU-PM5-3) a gap between two runs of one body that is one run of the walk's padding is the body's (one range); a jump across bytes
 *             nothing read that are not padding leaves its target NONE and the jumper INCOMPLETE
 *   flags     an indirect jump (a switch) makes INCOMPLETE; bytes that do not decode make BROKEN; a recursion cycle makes ASSUMED_RET on both functions;
 *             a block two entries reach makes SHARED on both
 *   high      a call into the middle of an exact (HIGH) body is dropped and counted (n_derive_into_high); the HIGH unit is unchanged; a call to its start is not
 *   arm       A32: the same shape as x86-64 with `b .` for g; a Thumb entry derives nothing and is counted (n_derive_skipped)
 *   cover     every byte of the code is in exactly one unit, every time (the table's invariant), and the units are sorted and apart
 *   decode    with the object's walk, every instruction the descent reads is the walk's (served == asked): one decode for every later reader
 *   cap       the derivation's bound of memory: over it nothing is derived and the table says so (P_DERIVE_CAP, OVER_BUDGET); under it the code is derived
 * Why the old tests missed it: (a) the derivation is new: before it, every case here was one NONE unit.
 * Why the old tests missed trap/hole (2026-11-17): (c) t_tail CHECKED the hole as a further range (it pinned the limit as the answer); no row had a trap
 * behind a dead call; the jump-across rows had either a read block or only padding in the gap, never unread code (b: no boundary input).
 */
#include "audit_pmeta_kit.h"

#include <phenotype/diag_private.h>
#include <genotype/image/fntab.h>

#define VB64 0x400000u
#define VB32 0x10000u
#define TX   0x100u             /* the file offset of .text */

static uint8_t img[4096];

/* An ET_EXEC object: .text = `code` at TX (n bytes), the entry at TX + `entry` (+ `thumb`), optionally a .symtab with one FUNC `hsz` bytes at TX + `hoff`. */
static size_t build(int is64, uint16_t machine, const uint8_t *code, size_t n, uint64_t entry, unsigned thumb, uint64_t hoff, uint64_t hsz)
{
	const uint64_t base = is64 ? VB64 : VB32;
	struct ak_elf e;
	static const char str[] = "\0h";
	const uint64_t at = (TX + n + 15u) & ~15ull;
	unsigned k = 1;

	memset(&e, 0, sizeof e);
	e.is64 = is64;
	e.machine = machine;
	e.etype = 2;
	e.base = base;
	e.entry = base + TX + entry + thumb;
	memset(img, 0, sizeof img);
	memcpy(img + TX, code, n);
	e.sec[k++] = (struct ak_sec){ ".text", 1, 6, TX, n, 0, 0, 0 };
	if (hsz) {
		const unsigned es = is64 ? 24u : 16u;

		e.sec[k] = (struct ak_sec){ ".symtab", 2, 0, at, 2u * es, k + 1u, 1, es };
		k++;
		e.sec[k++] = (struct ak_sec){ ".strtab", 3, 0, at + 2u * es, sizeof str, 0, 0, 0 };
		ak_sym(img, at + es, is64, 1, base + TX + hoff, hsz, (1 << 4) | 2, 1);
		memcpy(img + at + 2u * es, str, sizeof str);
	}
	e.nsec = k;
	return ak_elf_finish(img, sizeof img, &e, at + 0x80u, at + 0x100u);
}

/* The unit that starts at `off` (a file offset of .text: TX added), or NULL. */
static const struct kgenome_func *unit(const struct kgenome_func_set *fs, uint64_t off)
{
	const uint32_t i = kgenome_funcs_start(fs, TX + off);

	return i == KGENOME_FUNCS_NONE ? NULL : &fs->v[i];
}

static int derived(const struct kgenome_func *f, uint64_t len, uint16_t src, uint16_t flags)
{
	return f && f->trust == KGENOME_FN_TRUST_DERIVED && f->len == len && f->source == src && f->flags == flags && f->end_source == KGENOME_FN_E_REACH;
}

/* Every byte of [TX, TX + n) in exactly one unit (every range of every unit), the units sorted and apart. */
static int covered_once(const struct kgenome_func_set *fs, size_t n)
{
	static uint8_t hit[1024];
	uint32_t i, k;
	uint64_t o;

	memset(hit, 0, sizeof hit);
	for (i = 0; i < fs->n; i++) {
		if (i && fs->v[i - 1u].off + fs->v[i - 1u].len > fs->v[i].off)
			return 0;
		for (k = 0; k < kgenome_funcs_n_ranges(fs, i); k++) {
			const struct kgenome_func_range r = kgenome_funcs_range(fs, i, k);

			for (o = r.off; o < r.off + r.len; o++)
				if (o < TX || o >= TX + n || hit[o - TX]++)
					return 0;
		}
	}
	for (o = 0; o < n; o++)
		if (hit[o] != 1u)
			return 0;
	return 1;
}

/* entry `call f; call g; <garbage: call 0x2c>`; f `xor eax,eax; ret`; g: x86-64 `mov eax,60; syscall; ud2`, i386 `jmp $` */
static void t_noret(void)
{
	unsigned w;

	for (w = 0; w < 2; w++) {
		uint8_t c[0x30];
		struct kgenome_func_set fs;
		size_t n;

		printf("noret %s\n", w ? "i386 (g: jmp $)" : "x86-64 (g: syscall; ud2)");
		memset(c, 0xcc, sizeof c);
		memcpy(c, "\xe8\x0b\x00\x00\x00\xe8\x16\x00\x00\x00\xe8\x1d\x00\x00\x00", 15);
		memcpy(c + 0x10, "\x31\xc0\xc3", 3);
		if (w)
			memcpy(c + 0x20, "\xeb\xfe", 2);
		else
			memcpy(c + 0x20, "\xb8\x3c\x00\x00\x00\x0f\x05\x0f\x0b", 9);
		c[0x2c] = 0xc3;
		n = build(!w, w ? 3 : 62, c, sizeof c, 0, 0, 0, 0);
		CK(n && ak_table(img, n, &fs));
		CK(derived(unit(&fs, 0), 10, KGENOME_FN_S_ENTRY | KGENOME_FN_S_DERIVED_SEED, 0));
		CK(derived(unit(&fs, 0x10), 3, KGENOME_FN_S_DERIVED_CALL, 0));
		CK(derived(unit(&fs, 0x20), w ? 2 : 9, KGENOME_FN_S_DERIVED_CALL, 0));
		CK(unit(&fs, 0x0a) && unit(&fs, 0x0a)->trust == KGENOME_FN_TRUST_NONE && unit(&fs, 0x0a)->len == 6);    /* the garbage: undeclared, not read */
		CK(unit(&fs, 0x2c) == NULL && kgenome_funcs_at(&fs, TX + 0x2c) != KGENOME_FUNCS_NONE &&
		   fs.v[kgenome_funcs_at(&fs, TX + 0x2c)].trust == KGENOME_FN_TRUST_NONE);
		CK(fs.n == 6 && fs.n_undeclared == 3 && fs.n_derive_skipped == 0 && fs.n_derive_into_high == 0);
		CK(fs.ccase == KGENOME_FNTAB_C_NO_META && fs.state == KGENOME_FNTAB_PARTIAL &&
		   (fs.partial & (KGENOME_FNTAB_P_NO_META | KGENOME_FNTAB_P_UNDECLARED)) == (KGENOME_FNTAB_P_NO_META | KGENOME_FNTAB_P_UNDECLARED));
		CK(covered_once(&fs, sizeof c));
		kgenome_funcs_free(&fs);
	}
}

/* entry `call f; call g; call k; ret`; f `jmp g` (g is an entry: a tail call); g `ret`; k `jmp m` (m no call names: body, apart: a further range); m `ret` */
static void t_tail(void)
{
	uint8_t c[0x60];
	struct kgenome_func_set fs;
	const struct kgenome_func *k;
	struct kgenome_func_range r;
	size_t n;

	printf("tail jumps\n");
	memset(c, 0xcc, sizeof c);
	memcpy(c, "\xe8\x0b\x00\x00\x00\xe8\x16\x00\x00\x00\xe8\x21\x00\x00\x00\xc3", 16);
	memcpy(c + 0x10, "\xe9\x0b\x00\x00\x00", 5);
	c[0x20] = 0xc3;
	memcpy(c + 0x30, "\xe9\x1b\x00\x00\x00", 5);
	c[0x50] = 0xc3;
	n = build(1, 62, c, sizeof c, 0, 0, 0, 0);
	CK(n && ak_table(img, n, &fs));
	CK(derived(unit(&fs, 0), 16, KGENOME_FN_S_ENTRY | KGENOME_FN_S_DERIVED_SEED, 0));
	CK(derived(unit(&fs, 0x10), 5, KGENOME_FN_S_DERIVED_CALL, 0) && kgenome_funcs_n_ranges(&fs, kgenome_funcs_start(&fs, TX + 0x10)) == 1);
	CK(derived(unit(&fs, 0x20), 1, KGENOME_FN_S_DERIVED_CALL, 0));
	k = unit(&fs, 0x30);
	CK(k && k->trust == KGENOME_FN_TRUST_DERIVED && k->source == KGENOME_FN_S_DERIVED_CALL && k->flags == 0);
	if (k) {
		const uint32_t ki = (uint32_t)(k - fs.v);

		/* FU-PM5-3 (2026-11-17): the gap 0x35..0x50 is one run of int3 padding the walk saw, nothing read in it: a hole of k's body, so k is ONE range
		 * 0x30..0x51 (it was two ranges with a NONE unit between: RED before hole_is_body) */
		CK(kgenome_funcs_n_ranges(&fs, ki) == 1 && k->len == 0x21);
		CK(kgenome_funcs_at(&fs, TX + 0x50) == ki && kgenome_funcs_at(&fs, TX + 0x40) == ki);
	}
	CK(unit(&fs, 0x50) == NULL && covered_once(&fs, sizeof c));
	kgenome_funcs_free(&fs);
	/* a tail jump BACK to an entry below it is a tail call too (no SHARED: an entry is nobody's body); and a body block below its own entry is a further
	 * range, the first range starts at the entry: entry `call g; call k2; call q; ret`, g `ret`, k2 `jmp g`, q `jmp b` with b below q (`ret`) */
	memset(c, 0xcc, sizeof c);
	memcpy(c, "\xe8\x1b\x00\x00\x00\xe8\x26\x00\x00\x00\xe8\x31\x00\x00\x00\xc3", 16);   /* call 0x20; call 0x30; call 0x40 */
	c[0x20] = 0xc3;
	memcpy(c + 0x30, "\xeb\xee", 2);                                 /* k2 0x30: jmp 0x20 */
	c[0x38] = 0xc3;                                                     /* b 0x38 */
	memcpy(c + 0x40, "\xeb\xf6", 2);                                 /* q 0x40: jmp 0x38 */
	n = build(1, 62, c, sizeof c, 0, 0, 0, 0);
	CK(n && ak_table(img, n, &fs));
	CK(derived(unit(&fs, 0x30), 2, KGENOME_FN_S_DERIVED_CALL, 0) && derived(unit(&fs, 0x20), 1, KGENOME_FN_S_DERIVED_CALL, 0));
	k = unit(&fs, 0x40);
	CK(derived(k, 2, KGENOME_FN_S_DERIVED_CALL, 0));
	if (k) {
		const uint32_t ki = (uint32_t)(k - fs.v);

		r = kgenome_funcs_range(&fs, ki, 1);
		CK(kgenome_funcs_n_ranges(&fs, ki) == 2 && r.off == TX + 0x38 && r.len == 8 && kgenome_funcs_at(&fs, TX + 0x38) == ki);   /* b and the padding hole to q */
	}
	CK(covered_once(&fs, sizeof c));
	kgenome_funcs_free(&fs);
	/* PM5-D1: a tail jump ACROSS another function to a place no call names starts a function of its own (DERIVED_JUMP), it is not a range of the jumper:
	 * entry `call k3; call h; ret`, k3 `jmp m`, h `ret` (between k3 and m), m `ret`. RED before the fix: k3 held m as a second range. (The padding-only gap
	 * of k above stays a hole of one function.) */
	memset(c, 0xcc, sizeof c);
	memcpy(c, "\xe8\x2b\x00\x00\x00\xe8\x36\x00\x00\x00\xc3", 11);   /* call 0x30; call 0x40; ret */
	memcpy(c + 0x30, "\xe9\x1b\x00\x00\x00", 5);                       /* k3 0x30: jmp 0x50 */
	c[0x40] = 0xc3;                                                         /* h */
	c[0x50] = 0xc3;                                                         /* m */
	n = build(1, 62, c, sizeof c, 0, 0, 0, 0);
	CK(n && ak_table(img, n, &fs));
	CK(derived(unit(&fs, 0x30), 5, KGENOME_FN_S_DERIVED_CALL, 0) && kgenome_funcs_n_ranges(&fs, kgenome_funcs_start(&fs, TX + 0x30)) == 1);
	CK(derived(unit(&fs, 0x50), 1, KGENOME_FN_S_DERIVED_JUMP, 0) && derived(unit(&fs, 0x40), 1, KGENOME_FN_S_DERIVED_CALL, 0));
	CK(covered_once(&fs, sizeof c));
	kgenome_funcs_free(&fs);
	/* ... and across a byte of an exact (HIGH) unit: .symtab h FUNC 1 at 0x40, the same code */
	n = build(1, 62, c, sizeof c, 0, 0, 0x40, 1);
	CK(n && ak_table(img, n, &fs));
	CK(derived(unit(&fs, 0x50), 1, KGENOME_FN_S_DERIVED_JUMP, 0) && unit(&fs, 0x40) && unit(&fs, 0x40)->trust == KGENOME_FN_TRUST_HIGH);
	kgenome_funcs_free(&fs);
	/* the NEAREST other run decides: A `jmp T` with only padding between A and T (T stays A's, a hole), T `jmp U` across h (U starts a function) */
	{
		uint8_t c2[0x70];

		memset(c2, 0xcc, sizeof c2);
		memcpy(c2, "\xe8\x2b\x00\x00\x00\xe8\x46\x00\x00\x00\xc3", 11);   /* call 0x30; call 0x50; ret */
		memcpy(c2 + 0x30, "\xeb\x0e", 2);                                       /* A 0x30: jmp 0x40 */
		memcpy(c2 + 0x40, "\xe9\x1b\x00\x00\x00", 5);                        /* T 0x40: jmp 0x60 */
		c2[0x50] = 0xc3;                                                          /* h */
		c2[0x60] = 0xc3;                                                          /* U */
		n = build(1, 62, c2, sizeof c2, 0, 0, 0, 0);
		CK(n && ak_table(img, n, &fs));
		CK(derived(unit(&fs, 0x30), 0x15, KGENOME_FN_S_DERIVED_CALL, 0) && unit(&fs, 0x40) == NULL && kgenome_funcs_at(&fs, TX + 0x40) == kgenome_funcs_start(&fs, TX + 0x30));
		CK(derived(unit(&fs, 0x60), 1, KGENOME_FN_S_DERIVED_JUMP, 0) && covered_once(&fs, sizeof c2));
		kgenome_funcs_free(&fs);
	}
	/* a target a conditional branch of the same body also reaches stays body even across another function: k4 `je m2; jmp m2` */
	memset(c, 0xcc, sizeof c);
	memcpy(c, "\xe8\x2b\x00\x00\x00\xe8\x36\x00\x00\x00\xc3", 11);
	memcpy(c + 0x30, "\x74\x1e\xeb\x1c", 4);                              /* k4 0x30: je 0x50; jmp 0x50 */
	c[0x40] = 0xc3;
	c[0x50] = 0xc3;
	n = build(1, 62, c, sizeof c, 0, 0, 0, 0);
	CK(n && ak_table(img, n, &fs));
	CK(derived(unit(&fs, 0x30), 4, KGENOME_FN_S_DERIVED_CALL, 0) && unit(&fs, 0x50) == NULL && kgenome_funcs_n_ranges(&fs, kgenome_funcs_start(&fs, TX + 0x30)) == 2);
	kgenome_funcs_free(&fs);
	/* a jump across bytes nothing read that are NOT padding (a function nobody calls, or data of the jumper: not known): the target is neither body nor a
	 * start. k5 `jmp m3` over `mov rax,rdi; ret` that no path reads: m3's run is NONE and k5 is INCOMPLETE. RED before 2026-11-17: m3 was a range of k5. */
	memset(c, 0xcc, sizeof c);
	memcpy(c, "\xe8\x2b\x00\x00\x00\xc3", 6);                         /* call 0x30; ret */
	memcpy(c + 0x30, "\xeb\x1e", 2);                                       /* k5 0x30: jmp 0x50 */
	memcpy(c + 0x40, "\x48\x89\xf8\xc3", 4);                             /* unread code */
	c[0x50] = 0xc3;                                                         /* m3 */
	n = build(1, 62, c, sizeof c, 0, 0, 0, 0);
	CK(n && ak_table(img, n, &fs));
	CK(derived(unit(&fs, 0x30), 2, KGENOME_FN_S_DERIVED_CALL, KGENOME_FN_F_INCOMPLETE) && kgenome_funcs_n_ranges(&fs, kgenome_funcs_start(&fs, TX + 0x30)) == 1);
	CK(unit(&fs, 0x50) == NULL && kgenome_funcs_at(&fs, TX + 0x50) != KGENOME_FUNCS_NONE && fs.v[kgenome_funcs_at(&fs, TX + 0x50)].trust == KGENOME_FN_TRUST_NONE);
	CK(covered_once(&fs, sizeof c));
	kgenome_funcs_free(&fs);
}

/* PM5-D2 (2026-11-17): the trap behind a call that does not return is the caller's. entry `call g; <T>` with g `jmp $` (x86-64): T = ud2 (0f 0b), hlt (f4),
 * int3 (cc) is in the entry's function; T = nop (90) is not a trap and stays NONE (it may be another function's first byte). RED before cfg_obj.c traps():
 * the entry was 5 bytes and T a NONE unit. */
static void t_trap(void)
{
	static const struct { const char *t; unsigned n, keep; } k[] = { { "\x0f\x0b", 2, 1 }, { "\xf4", 1, 1 }, { "\xcc", 1, 1 }, { "\x90", 1, 0 } };
	unsigned w;

	printf("trap behind a call that does not return\n");
	for (w = 0; w < 4u; w++) {
		uint8_t c[0x20];
		struct kgenome_func_set fs;
		size_t n;

		memset(c, 0x00, sizeof c);                      /* zeros: `add [rax],al`, neither padding nor a trap */
		memcpy(c, "\xe8\x0b\x00\x00\x00", 5);          /* call 0x10 */
		memcpy(c + 5, k[w].t, k[w].n);
		memcpy(c + 0x10, "\xeb\xfe", 2);                 /* g: jmp $ */
		n = build(1, 62, c, sizeof c, 0, 0, 0, 0);
		CK(n && ak_table(img, n, &fs));
		CK(derived(unit(&fs, 0), 5u + (k[w].keep ? k[w].n : 0u), KGENOME_FN_S_ENTRY | KGENOME_FN_S_DERIVED_SEED, 0));
		CK(derived(unit(&fs, 0x10), 2, KGENOME_FN_S_DERIVED_CALL, 0));
		CK(k[w].keep ? kgenome_funcs_at(&fs, TX + 5) == kgenome_funcs_start(&fs, TX) : unit(&fs, 5) && unit(&fs, 5)->trust == KGENOME_FN_TRUST_NONE);
		CK(covered_once(&fs, sizeof c));
		kgenome_funcs_free(&fs);
	}
}

/* entry `call f; call g; call a; call b; ret`; f `jmp [rax*8+0x1000]` (a switch: INCOMPLETE); g `nop; <undecodable>` (BROKEN; a stop may return, so the entry
 * goes on); a `je x; ret`, b `je x; ret`, x `ret` (x reached by a conditional branch from two entries: SHARED on both, x is a's) */
static void t_flags(void)
{
	uint8_t c[0x60];
	struct kgenome_func_set fs;
	size_t n;

	printf("flags\n");
	memset(c, 0xcc, sizeof c);
	memcpy(c, "\xe8\x1b\x00\x00\x00\xe8\x26\x00\x00\x00\xe8\x2b\x00\x00\x00\xe8\x2c\x00\x00\x00\xc3", 21); /* f 0x20, g 0x30, a 0x3a, b 0x40 */
	memcpy(c + 0x20, "\xff\x24\xc5\x00\x10\x00\x00", 7);
	memcpy(c + 0x30, "\x90\x06", 2);
	memcpy(c + 0x3a, "\x74\x0a\xc3", 3);                                /* a 0x3a: je 0x46; ret */
	memcpy(c + 0x40, "\x74\x04\xc3", 3);                                /* b 0x40: je 0x46; ret */
	c[0x46] = 0xc3;
	n = build(1, 62, c, sizeof c, 0, 0, 0, 0);
	CK(n && ak_table(img, n, &fs));
	CK(derived(unit(&fs, 0), 21, KGENOME_FN_S_ENTRY | KGENOME_FN_S_DERIVED_SEED, 0));
	CK(derived(unit(&fs, 0x20), 7, KGENOME_FN_S_DERIVED_CALL, KGENOME_FN_F_INCOMPLETE));
	CK(derived(unit(&fs, 0x30), 1, KGENOME_FN_S_DERIVED_CALL, KGENOME_FN_F_BROKEN));
	CK(derived(unit(&fs, 0x3a), 3, KGENOME_FN_S_DERIVED_CALL, KGENOME_FN_F_SHARED));
	CK(derived(unit(&fs, 0x40), 3, KGENOME_FN_S_DERIVED_CALL, KGENOME_FN_F_SHARED));
	CK(kgenome_funcs_at(&fs, TX + 0x46) == kgenome_funcs_start(&fs, TX + 0x3a));
	CK(covered_once(&fs, sizeof c));
	kgenome_funcs_free(&fs);
}

/* f `call g; ret`, g `call f; ret`: whether either returns depends on the other: both RESOLVED AS RETURNING, said on both (ASSUMED_RET); the entry is not */
static void t_recursion(void)
{
	uint8_t c[0x30];
	struct kgenome_func_set fs;
	size_t n;

	printf("recursion\n");
	memset(c, 0xcc, sizeof c);
	memcpy(c, "\xe8\x0b\x00\x00\x00\xc3", 6);
	memcpy(c + 0x10, "\xe8\x0b\x00\x00\x00\xc3", 6);
	memcpy(c + 0x20, "\xe8\xeb\xff\xff\xff\xc3", 6);
	n = build(1, 62, c, sizeof c, 0, 0, 0, 0);
	CK(n && ak_table(img, n, &fs));
	CK(derived(unit(&fs, 0), 6, KGENOME_FN_S_ENTRY | KGENOME_FN_S_DERIVED_SEED, 0));
	CK(derived(unit(&fs, 0x10), 6, KGENOME_FN_S_DERIVED_CALL, KGENOME_FN_F_ASSUMED_RET));
	CK(derived(unit(&fs, 0x20), 6, KGENOME_FN_S_DERIVED_CALL, KGENOME_FN_F_ASSUMED_RET));
	kgenome_funcs_free(&fs);
}

/* .symtab: h FUNC 8 at 0x40 (HIGH). The entry (in the gap before it): `call h+3; call h; ret`. The call into the middle of h is dropped and counted; the
 * call to h's start is not; h is untouched; both calls are assumed to return (h is not read by the descent) */
static void t_high(void)
{
	uint8_t c[0x50];
	struct kgenome_func_set fs;
	const struct kgenome_func *h;
	size_t n;

	printf("into a HIGH body\n");
	memset(c, 0xcc, sizeof c);
	memcpy(c, "\xe8\x3e\x00\x00\x00\xe8\x36\x00\x00\x00\xc3", 11);   /* 0: call 0x43; 5: call 0x40; 0xa: ret */
	memcpy(c + 0x40, "\x90\x90\x90\x90\x90\x90\x90\xc3", 8);
	n = build(1, 62, c, sizeof c, 0, 0, 0x40, 8);
	CK(n && ak_table(img, n, &fs));
	h = unit(&fs, 0x40);
	CK(h && h->trust == KGENOME_FN_TRUST_HIGH && h->len == 8 && h->source == KGENOME_FN_S_SYMTAB);
	CK(derived(unit(&fs, 0), 11, KGENOME_FN_S_ENTRY | KGENOME_FN_S_DERIVED_SEED, 0));
	CK(fs.n_derive_into_high == 1 && fs.n_derive_skipped == 0 && covered_once(&fs, sizeof c));
	kgenome_funcs_free(&fs);
}

/* A32 LE: entry `bl f; bl g; <garbage: bl 0x20>`; f `bx lr`; g `b g`. A Thumb entry (e_entry bit 0) derives nothing and is counted. */
static void t_arm(void)
{
	uint8_t c[0x28];
	struct kgenome_func_set fs;
	size_t n;

	printf("arm\n");
	memset(c, 0, sizeof c);
	memcpy(c, "\x02\x00\x00\xeb\x02\x00\x00\xeb\x04\x00\x00\xeb", 12);
	memcpy(c + 0x10, "\x1e\xff\x2f\xe1\xfe\xff\xff\xea", 8);
	memcpy(c + 0x20, "\x1e\xff\x2f\xe1", 4);
	n = build(0, 40, c, sizeof c, 0, 0, 0, 0);
	CK(n && ak_table(img, n, &fs));
	CK(derived(unit(&fs, 0), 8, KGENOME_FN_S_ENTRY | KGENOME_FN_S_DERIVED_SEED, 0));
	CK(derived(unit(&fs, 0x10), 4, KGENOME_FN_S_DERIVED_CALL, 0) && derived(unit(&fs, 0x14), 4, KGENOME_FN_S_DERIVED_CALL, 0));
	CK(unit(&fs, 8) && unit(&fs, 8)->trust == KGENOME_FN_TRUST_NONE && unit(&fs, 0x20) == NULL && covered_once(&fs, sizeof c));
	kgenome_funcs_free(&fs);
	n = build(0, 40, c, sizeof c, 0, 1, 0, 0);
	CK(n && ak_table(img, n, &fs));
	CK(fs.n == 1 && fs.v[0].trust == KGENOME_FN_TRUST_NONE && fs.n_derive_skipped == 1 && covered_once(&fs, sizeof c));
	kgenome_funcs_free(&fs);
}

/* With the object's walk: the same table, and every instruction the descent read was answered by the walk's trace (one decode for every later reader). */
static void t_walk(void)
{
	uint8_t c[0x30];
	static struct kgenome_elf_info ei;
	struct kgenome_obj obj;
	struct kgenome_func_set a, b;
	struct kgenome_diag_walk *wk = kgenome_diag_walk_new();
	uint64_t asked = 0, served;
	size_t n;
	uint32_t i;
	int same;

	printf("one decode with the walk\n");
	memset(c, 0xcc, sizeof c);
	memcpy(c, "\xe8\x0b\x00\x00\x00\xe8\x16\x00\x00\x00\xe8\x1d\x00\x00\x00", 15);
	memcpy(c + 0x10, "\x31\xc0\xc3", 3);
	memcpy(c + 0x20, "\xb8\x3c\x00\x00\x00\x0f\x05\x0f\x0b", 9);
	c[0x2c] = 0xc3;
	n = build(1, 62, c, sizeof c, 0, 0, 0, 0);
	CK(n && ak_table(img, n, &a));
	memset(&ei, 0, sizeof ei);
	memset(&obj, 0, sizeof obj);
	CK(wk && kgenome_elf_image_parse(kof_buf_make(img, n), &ei, &obj));
	obj.file_header = &ei;
	kgenome_diag_funcs_with_walk(&obj, img, n, wk, &b);
	same = a.n == b.n;
	for (i = 0; same && i < a.n; i++)
		same = a.v[i].off == b.v[i].off && a.v[i].len == b.v[i].len && a.v[i].trust == b.v[i].trust && a.v[i].source == b.v[i].source &&
		       a.v[i].flags == b.v[i].flags;
	CK(same);
	served = kgenome_diag_walk_held_count(wk, &asked);
	CK(asked == 8 && served == asked);      /* 7 read, and the place behind the call to g that does not return, looked at for a trap (cfg_obj.c traps): served too */
	kgenome_funcs_free(&a);
	kgenome_funcs_free(&b);
	kgenome_diag_walk_free(wk);
}

/* The bound of memory of the derivation (KGENOME_FNTAB_DERIVE_BYTES): an undeclared extent whose map alone (five bytes a byte) is over it derives nothing and
 * says so (P_DERIVE_CAP, state OVER_BUDGET); the code stays one NONE unit. Just under it: the derivation runs. */
static void t_cap(void)
{
	const size_t big = (size_t)(KGENOME_FNTAB_DERIVE_BYTES / 5u) + 0x1000u, small = 0x10000u;
	uint8_t *b = malloc(big + 0x1000u);
	unsigned w;

	printf("the derivation's bound of memory\n");
	CK(b != NULL);
	for (w = 0; b && w < 2; w++) {
		const size_t n_text = w ? small : big;
		struct ak_elf e;
		struct kgenome_elf_info ei;
		struct kgenome_obj obj;
		struct kgenome_func_set fs;
		size_t n;

		memset(&e, 0, sizeof e);
		e.is64 = 1;
		e.machine = 62;
		e.etype = 2;
		e.base = VB64;
		e.entry = VB64 + TX;
		memset(b, 0, big + 0x1000u);
		memset(b + TX, 0x90, n_text);
		b[TX + n_text - 1u] = 0xc3;
		e.sec[1] = (struct ak_sec){ ".text", 1, 6, TX, n_text, 0, 0, 0 };
		e.nsec = 2;
		n = ak_elf_finish(b, big + 0x1000u, &e, TX + n_text + 0x10u, TX + n_text + 0x100u);
		memset(&ei, 0, sizeof ei);
		memset(&obj, 0, sizeof obj);
		CK(n && kgenome_elf_image_parse(kof_buf_make(b, n), &ei, &obj));
		obj.file_header = &ei;
		kgenome_diag_funcs_of(&obj, b, n, &fs);
		if (w)
			CK(fs.n == 1 && fs.v[0].trust == KGENOME_FN_TRUST_DERIVED && fs.v[0].len == n_text && !(fs.partial & KGENOME_FNTAB_P_DERIVE_CAP) &&
			   fs.state == KGENOME_FNTAB_PARTIAL);
		else
			CK(fs.n == 1 && fs.v[0].trust == KGENOME_FN_TRUST_NONE && fs.v[0].len == n_text && (fs.partial & KGENOME_FNTAB_P_DERIVE_CAP) &&
			   fs.state == KGENOME_FNTAB_OVER_BUDGET);
		kgenome_funcs_free(&fs);
	}
	free(b);
}

int main(void)
{
	t_trap();
	t_noret();
	t_tail();
	t_flags();
	t_recursion();
	t_high();
	t_arm();
	t_walk();
	t_cap();
	printf("fntab_derive: %d failure(s)\n", hk_fails);
	return hk_fails != 0;
}
