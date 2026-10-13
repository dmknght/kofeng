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
#include <kofshared/msf_elf32.h>
#include <kofmod/stub_pat.h>
KOF_ANALYZE_STEP(KOF_ANALYZE_DECRYPT);

/* ELF and the formatless children, for the reason msf_xor_00.c gives: these can
 * sit under another encoder, and the layer below has no header. */
KOF_TARGET_FORMAT(KOF_FMT_ELF | KOF_FMT_PE | KOF_FMT_UNKNOWN);
KOF_TARGET_CONTENT("Sub");

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

/*
 * Does the run of fixed bytes at `ep` match row `c`? Reads inside the object
 * only, so a file that ends inside the pattern matches nothing.
 *
 * The function is defined by KOF_STUB_DEFINE_IS (kofmod/stub_pat.h), because the
 * other msf_x86 module needs the same one. It is invoked HERE, in the place the
 * function had, and this comment is as long as the function was: a blob follows
 * the order its functions are emitted in, and a report carries the line it was
 * made on, so moving code in a module changes the pack even when nothing it does
 * has changed.
 *
 *
 */
KOF_STUB_DEFINE_IS(stub_is, coding, stub_pat)

KOF_DEFINE_UNPACK
{
	uint8_t buf[SUB_MAX_DWORDS * 4u];
	uint8_t sub[256];
	uint64_t ep;
	uint32_t c, found = N_CODING, n = 0;
	struct kof_capsid capsid;

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

	/*
	 * THE ARITHMETIC IS THE HOST'S - see kofmod/kofdecode.h. This module says which
	 * of the two stubs it is looking at and reads the parameters out of it; the
	 * transform is a descriptor.
	 */
	capsid.k32 = 0;
	capsid.key = 0;
	capsid.key_len = 0;
	capsid.max_out = 0;
	if (coding[found].code == S_PLACE) {
		uint8_t dd   = kof_u8(ep + PLACE_DD);
		uint8_t mark = kof_u8(ep + PLACE_MARK);
		uint64_t body = ep + PLACE_BODY;
		uint32_t src;

		/* The subtrahends sit at the start of the body and the template follows
		 * them, `dd` bytes in. */
		for (src = 0; src < dd; src++)
			sub[src] = kof_u8(body + src);
		capsid.algo = KOF_CAPSID_PLACEHOLDER_SUB;
		capsid.k32 = mark;
		capsid.key = sub;
		capsid.key_len = dd;
		n = kunp_decrypt_peek(&capsid, body + dd, CHUNK, buf, CHUNK);
		if (n < PLAIN_MIN)
			return;
		if (!msf_emit_hdr(ctx, n))
			return;
		if (!kunp_decrypt(&capsid, body + dd, CHUNK))
			return;
	} else {
		/* The chain is read from the stub's own first byte, to the end of the
		 * object: the host stops at the first opcode that is not part of it. */
		uint64_t rest = ctx->obj_size - ep;

		capsid.algo = KOF_CAPSID_X86_SUB_CHAIN;
		capsid.max_out = sizeof buf;    /* at most 512 dwords, as the module always took */
		n = kunp_decrypt_peek(&capsid, ep, rest, buf, sizeof buf);
		if (n < PLAIN_MIN)
			return;
		if (!msf_emit_hdr(ctx, n))
			return;
		if (!kunp_decrypt(&capsid, ep, rest))
			return;
	}

	kunp_rcstruct_supersedes();
	if (!kunp_rcstruct_done())
		kunp_rcstruct_broken(KOF_UNP_LIMIT);
}
