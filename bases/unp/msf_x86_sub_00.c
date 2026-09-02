/*
 * msf_x86_sub_00.c - msfvenom's x86 encoders that SUBTRACT rather than XOR.
 *
 * Three codings, one family, and the family is what they have in common at the
 * arithmetic level: none of them XORs anything. Two of them rebuild the payload
 * by subtracting a byte from a placeholder; the third rebuilds it a dword at a
 * time out of chains of `sub eax, imm32` and pushes the result onto the stack.
 * Grouped for the reason msf_x86_dword_00.c states and upx_elf demonstrates: the
 * plumbing around a transform is the whole of a module, and three copies of it
 * would be three places for one bug.
 *
 *
 * x86/nonalpha AND x86/nonupper - ONE STUB, ONE BYTE APART
 *
 *     66 b9 ff ff        mov  cx, 0xffff
 *     eb 19              jmp  +0x19
 *     5e                 pop  esi          the body, from the call below
 *     8b fe              mov  edi, esi
 *     83 c7 DD           add  edi, DD      where the TEMPLATE starts
 *     8b d7              mov  edx, edi
 *     3b f2              cmp  esi, edx
 *     7d 0b              jge  done
 *     b0 MM              mov  al, MM       the placeholder byte
 *     f2 ae              repnz scasb       find the next MM at or after edi
 *     ff cf              dec  edi          back onto it
 *     ac                 lodsb             al = the next subtrahend
 *     28 07              sub  [edi], al    MM - al is the plaintext byte
 *     eb f1              jmp  loop
 *     eb NN              jmp  the template
 *     e8 e2 ff ff ff     call -0x1e        pushes the address of the body
 *
 * The body is <DD subtrahend bytes><template>, and the template is the payload
 * with every byte that the encoder could not emit replaced by MM. Each
 * placeholder is repaired with MM minus the next subtrahend.
 *
 * THE TWO DIFFER ONLY IN DD. nonupper's is zero, which makes `cmp esi, edx`
 * true on the first test, skips the loop entirely, and runs a template that is
 * already the payload - so the same code decodes both and the second is the
 * degenerate case of the first rather than a coding of its own.
 *
 *
 * x86/opt_sub - ARITHMETIC ONTO THE STACK
 *
 *     54 58              push esp; pop eax
 *     2d ...             sub eax, imm32     x3, to place the new stack
 *     50 5c              push eax; pop esp
 *     25 00000000        and eax, 0         twice: eax = 0
 *     25 00000000
 *   then, repeatedly:
 *     2d ...             sub eax, imm32     as many as the encoder needed
 *     50                 push eax           one dword of the payload
 *
 * There is no key and nothing is encrypted: each dword is simply expressed as a
 * subtraction chain from the running value of eax, which is the only way the
 * encoder can produce a dword out of bytes it is allowed to emit. Decoding is
 * therefore running the arithmetic - the module keeps one 32-bit accumulator and
 * records what each `push` would have pushed.
 *
 * IN REVERSE, because a push moves DOWN. The first dword pushed ends at the
 * highest address and is therefore the LAST dword of the payload, so the
 * recorded values are emitted back to front. This is the one place the module
 * has to hold the whole payload before it can emit any of it.
 *
 * The payload it rebuilds is a whole number of dwords, so msfvenom pads it -
 * with 0x90, a NOP, at the FRONT. The padding is emitted rather than trimmed:
 * trimming would mean deciding how many leading NOPs were the encoder's and how
 * many were the payload's, and the payload is entitled to start with one.
 */

#include <kofmod/kofsig.h>
#include "msf_elf32.h"

KOF_UNPACK_KIND(KOF_UNP_PACKER);

/* ELF and the formatless children, for the reason msf_xor_00.c gives: these can
 * sit under another encoder, and the layer below has no header. */
KOF_TARGET_FORMAT(KOF_FMT_ELF | KOF_FMT_UNKNOWN);

/* The family, so a Meterp prediction routes here first. */
KOF_TARGET_NAME(KOF_MALTYPE_TROJAN, "Meterp");

#define PLAIN_MIN   32u
#define CHUNK       1024u

/*
 * The most dwords opt_sub will be followed for.
 *
 * A stager is thirty-one; the ceiling is far above that and exists so a stream
 * of 0x2d bytes in data cannot make the walk unbounded. kof_in_obj is what
 * actually stops it at the end of the object; this stops it before that on an
 * object made entirely of subtractions.
 */
#define SUB_MAX_DWORDS 512u

/*
 * The two stubs, flattened into one array so the table can hold an index rather
 * than a pointer: a pointer needs a relocation, and a module is not allowed
 * writable data. 0x100 marks a byte that varies.
 */
static const uint16_t stub_pat[] = {
	/* --- S_PLACE, 36 --- the nonalpha / nonupper stub --- */
	0x66,0xb9,0xff,0xff,           /* mov cx, 0xffff                */
	0xeb,0x19,                     /* jmp +0x19                     */
	0x5e,                          /* pop esi                       */
	0x8b,0xfe,                     /* mov edi, esi                  */
	0x83,0xc7,0x100,               /* add edi, DD                   */
	0x8b,0xd7,                     /* mov edx, edi                  */
	0x3b,0xf2,                     /* cmp esi, edx                  */
	0x7d,0x0b,                     /* jge done                      */
	0xb0,0x100,                    /* mov al, MM                    */
	0xf2,0xae,                     /* repnz scasb                   */
	0xff,0xcf,                     /* dec edi                       */
	0xac,                          /* lodsb                         */
	0x28,0x07,                     /* sub [edi], al                 */
	0xeb,0xf1,                     /* jmp loop                      */
	0xeb,0x100,                    /* jmp the template              */
	0xe8,0xe2,0xff,0xff,0xff,      /* call -0x1e                    */
	/* --- S_SUB, 7 (at 36) --- the opt_sub prologue --- */
	0x54,0x58,                     /* push esp; pop eax             */
	0x2d,0x100,0x100,0x100,0x100   /* sub eax, imm32                */
};

enum { S_PLACE = 1, S_SUB = 2 };

static const struct {
	uint32_t at, n, code;
} coding[] = {
	{  0u, 36u, S_PLACE },
	{ 36u,  7u, S_SUB   }
};

#define N_CODING (sizeof coding / sizeof coding[0])

/* The rows have to cover the array, or one is reading another's bytes. This
 * check has already earned its place once, in msf_x86_dword_00.c. */
typedef char coding_rows_cover_stub_pat[
	(36u + 7u) == (sizeof stub_pat / sizeof stub_pat[0]) ? 1 : -1];

/* Where the placeholder stub's body is: what its trailing call pushes, which is
 * the byte after the five-byte call at offset 26. */
#define PLACE_BODY  36u
/* The two variable bytes inside it. */
#define PLACE_DD    11u
#define PLACE_MARK  19u

static int stub_is(const struct kof_obj_ctx *ctx, uint64_t ep, uint32_t c)
{
	uint32_t i;

	if (!kof_in_obj(ep, coding[c].n))
		return 0;
	for (i = 0; i < coding[c].n; i++) {
		uint16_t w = stub_pat[coding[c].at + i];

		if (w != 0x100u && kof_u8(ep + i) != (uint8_t)w)
			return 0;
	}
	return 1;
}

/*
 * nonalpha / nonupper. Returns the number of bytes emitted, or 0.
 *
 * The template is repaired in place in a buffer rather than in the object,
 * because a module may not write to what it is reading - so the whole template
 * is copied out first and the placeholders are filled in the copy.
 */
static uint32_t do_place(const struct kof_obj_ctx *ctx, uint64_t ep,
			 uint8_t *out, uint32_t cap)
{
	uint8_t dd   = kof_u8(ep + PLACE_DD);
	uint8_t mark = kof_u8(ep + PLACE_MARK);
	uint64_t body = ep + PLACE_BODY;
	uint64_t tpl  = body + dd;
	uint32_t n = 0, src = 0, at = 0;

	/*
	 * No ceiling on dd is needed and none is written: it is the imm8 of an
	 * `add edi, imm8`, so it cannot exceed 255, and the loop below is bounded
	 * by it and by the end of the template either way.
	 */
	/* The template: everything from where the stub jumps to, to the end. */
	while (n < cap && kof_in_obj(tpl + n, 1)) {
		out[n] = kof_u8(tpl + n);
		n++;
	}
	if (n < PLAIN_MIN)
		return 0;

	/*
	 * One subtrahend per placeholder, in order. The stub walks esi over the
	 * DD bytes in front of the template and edi over the placeholders, and
	 * stops when they meet - which here is simply "until the subtrahends run
	 * out", because esi cannot pass edi while edi is still finding them.
	 */
	for (src = 0; src < dd; src++) {
		while (at < n && out[at] != mark)
			at++;
		if (at >= n)
			break;          /* fewer placeholders than subtrahends */
		out[at] = (uint8_t)(mark - kof_u8(body + src));
		at++;
	}
	return n;
}

/*
 * opt_sub. Returns the number of dwords recorded into `dw`, or 0.
 *
 * Faithful to the instruction stream: the accumulator starts at whatever the
 * prologue leaves and the `and eax, 0` pair is what zeroes it, so this does not
 * assume a starting value - a build that zeroed eax some other way would still
 * be followed correctly.
 */
static uint32_t do_sub(const struct kof_obj_ctx *ctx, uint64_t ep,
		       uint32_t *dw, uint32_t cap)
{
	uint64_t at = ep;
	uint32_t eax = 0, n = 0;
	int zeroed = 0;

	while (kof_in_obj(at, 1) && n < cap) {
		uint8_t op = kof_u8(at);

		if (op == 0x2du) {              /* sub eax, imm32 */
			if (!kof_in_obj(at, 5))
				break;
			eax -= kof_u32(at + 1u);
			at += 5u;
		} else if (op == 0x25u) {       /* and eax, imm32 */
			if (!kof_in_obj(at, 5))
				break;
			eax &= kof_u32(at + 1u);
			/*
			 * The zeroing is what separates the stack setup from
			 * the payload, so recording starts here rather than at
			 * a fixed offset.
			 */
			if (!eax)
				zeroed = 1;
			at += 5u;
		} else if (op == 0x50u) {       /* push eax */
			if (zeroed)
				dw[n++] = eax;
			at += 1u;
		} else if (op == 0x54u || op == 0x58u || op == 0x5cu) {
			at += 1u;               /* push esp / pop eax / pop esp */
		} else {
			break;                  /* not part of the chain */
		}
	}
	return n;
}

KOF_DEFINE_UNPACK
{
	uint8_t buf[CHUNK];
	uint32_t dw[SUB_MAX_DWORDS];
	uint64_t ep;
	uint32_t c, found = N_CODING, n = 0;

	ep = ctx->entry_off;
	if (ep == KOF_NA || ep == KOF_BROKEN)
		ep = 0;

	for (c = 0; c < N_CODING; c++)
		if (stub_is(ctx, ep, c)) {
			found = c;
			break;
		}
	if (found == N_CODING)
		return;

	kof_debug("MSF.x86.sub", coding[found].code);

	if (coding[found].code == S_PLACE) {
		n = do_place(ctx, ep, buf, CHUNK);
		if (n < PLAIN_MIN)
			return;
		/* The ELF32 header first, so the child is a file. See
		 * msf_elf32.h. */
		if (!msf_emit_elf32(ctx, n))
			return;
		if (!kof_emit(buf, n))
			return;
	} else {
		uint32_t k = do_sub(ctx, ep, dw, SUB_MAX_DWORDS);
		uint32_t i;

		if (k * 4u < PLAIN_MIN)
			return;
		if (!msf_emit_elf32(ctx, k * 4u))
			return;
		/*
		 * BACK TO FRONT: a push moves down, so the first dword recorded
		 * is the payload's last. Emitted in chunks so a long payload
		 * still costs a fixed amount of stack.
		 */
		n = 0;
		for (i = k; i-- > 0; ) {
			uint32_t b;

			for (b = 0; b < 4u; b++) {
				buf[n++] = (uint8_t)(dw[i] >> (b * 8));
				if (n == CHUNK) {
					if (!kof_emit(buf, n))
						return;
					n = 0;
				}
			}
		}
		if (n && !kof_emit(buf, n))
			return;
	}

	/* Checked, for the reason ezuri.c gives: reporting nothing after the host
	 * refused the child would claim an unpacking that did not happen. */
	if (!kof_child())
		kof_unp_broken(KOF_UNP_LIMIT);
}
