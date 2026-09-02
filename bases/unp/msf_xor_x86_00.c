/*
 * msf_xor_x86_00.c - msfvenom's x86/xor_dynamic wrapper, one layer per pass.
 *
 * THE 32-BIT SIBLING OF msf_xor_00.c, and a separate file rather than a branch
 * inside it because the two share an algorithm and not a single byte of stub:
 * every register reference differs, the prologue is two bytes shorter, and the
 * order of the marker test and the key advance is swapped. A module that tried
 * to be both would be two byte tables and two offset sets behind one name, and
 * the ABI's one-format-one-view rule exists to stop exactly that.
 *
 * What IS shared is the shape of the wrapper, so the reasoning in msf_xor_00.c
 * about why each field is read from the stub rather than assumed applies here
 * word for word. The short version: msfvenom picks the terminator, the two byte
 * end marker and the key per sample, so a module that spells any of them as a
 * constant opens the one sample it was written against and reads the others past
 * their real end.
 *
 *
 * THE STUB, AS THE SAMPLE HAS IT
 *
 *     eb 23              jmp  +0x23        over the key and the ciphertext
 *     5b                 pop  ebx          the address the call below pushed
 *     89 df              mov  edi, ebx
 *     b0 TT              mov  al, TT       the key terminator
 *     fc                 cld
 *     ae                 scasb             walk edi to the terminator
 *     75 fd              jne  -3
 *     89 f9              mov  ecx, edi     one past it: the ciphertext
 *     89 de              mov  esi, ebx     back to the start of the key
 *     8a 06              mov  al, [esi]
 *     30 07              xor  [edi], al
 *     47                 inc  edi
 *     66 81 3f LL HH     cmp  word [edi], HHLL     the end marker
 *     74 08              je   +8           done: jump into the plaintext
 *     46                 inc  esi
 *     80 3e TT           cmp  byte [esi], TT       key exhausted?
 *     75 ee              jne  -0x12        no: next byte
 *     eb ea              jmp  -0x16        yes: rewind the key
 *     ff e1              jmp  ecx
 *     e8 d8 ff ff ff     call -0x28        pushes the address of `pop ebx`
 *
 * and then <key> TT <ciphertext> HHLL.
 *
 * NOTE THE MARKER IS TESTED AFTER edi ADVANCES AND BEFORE esi DOES, which is
 * the opposite nesting from the amd64 stub. It changes nothing about what the
 * loop produces - the marker is still read from the ciphertext before that byte
 * is decrypted - but it is why the byte offsets below are what they are and not
 * the ones in msf_xor_00.c.
 */

#include <kofmod/kofsig.h>

KOF_UNPACK_KIND(KOF_UNP_PACKER);

/*
 * ELF and the formatless children, for the reason msf_xor_00.c gives: the layers
 * after the first have no header of their own, and a module that named only ELF
 * peeled one layer of a sample wrapped three times.
 */
KOF_TARGET_FORMAT(KOF_FMT_ELF | KOF_FMT_UNKNOWN);

/* The family this decodes, so a heuristic that predicts Meterp routes here
 * first. See the same declaration in msf_xor_00.c. */
KOF_TARGET_NAME(KOF_MALTYPE_TROJAN, "Meterp");

/*
 * NO ARCHITECTURE IS DECLARED. The stub is i386 machine code, but the objects
 * after the first carry KOF_ARCH_ANY - a formatless child has no architecture to
 * compare against - and a declared arch would rule this module out for every
 * layer but the outermost. Thirty-seven bytes matched exactly is a far narrower
 * filter than an architecture, and it fails on the first byte that differs.
 */

/* Where the pieces sit, relative to the stub's first byte. Named because each is
 * a fact about the listing above that a reader has to be able to check. */
#define STUB_TERM_AT   6u              /* the imm8 of `mov al, TT`          */
#define STUB_MARK_AT   23u             /* the imm16 of `cmp word [edi], ..` */
#define STUB_TERM2_AT  30u             /* the imm8 of `cmp byte [esi], TT`  */
#define STUB_CALL_AT   37u             /* the `e8` of the GetPC call        */
#define STUB_KEY_AT    42u             /* one past it: what the call pushes */
#define STUB_LEN       STUB_KEY_AT

/* The longest key this follows. The scasb in the stub has no bound at all, but a
 * key running for kilobytes is a file whose terminator never appears - not this
 * format - and following it would decrypt against noise. */
#define KEY_MAX        256u

/* Below this the plaintext cannot be a payload. The smallest thing msfvenom
 * wraps is a stager, and the x86 one measured here is 123 bytes. */
#define PLAIN_MIN      32u

/* How much is decrypted before it is handed over, so a large payload costs a
 * fixed amount of stack. */
#define CHUNK          1024u

/*
 * The fixed bytes, with 0x100 standing for "the terminator, whatever this
 * sample chose" - it appears twice and the two must agree - and 0x101 for the
 * two marker bytes, which are unconstrained and are read rather than checked.
 */
static const uint16_t stub_want[STUB_LEN] = {
	0xeb,0x23,                     /* jmp +0x23                  */
	0x5b,                          /* pop ebx                    */
	0x89,0xdf,                     /* mov edi, ebx               */
	0xb0,0x100,                    /* mov al, TT                 */
	0xfc,                          /* cld                        */
	0xae,0x75,0xfd,                /* scasb; jne -3              */
	0x89,0xf9,                     /* mov ecx, edi               */
	0x89,0xde,                     /* mov esi, ebx               */
	0x8a,0x06,                     /* mov al, [esi]              */
	0x30,0x07,                     /* xor [edi], al              */
	0x47,                          /* inc edi                    */
	0x66,0x81,0x3f,0x101,0x101,    /* cmp word [edi], HHLL       */
	0x74,0x08,                     /* je +8                      */
	0x46,                          /* inc esi                    */
	0x80,0x3e,0x100,               /* cmp byte [esi], TT         */
	0x75,0xee,                     /* jne -0x12                  */
	0xeb,0xea,                     /* jmp -0x16                  */
	0xff,0xe1,                     /* jmp ecx                    */
	0xe8,0xd8,0xff,0xff,0xff       /* call -0x28                 */
};

/*
 * Is the stub at `ep` this stub? Every byte of the fixed part is checked, for
 * the reason msf_xor_00.c gives: the prefix that would identify it - a jump, a
 * pop, a mov - is ordinary code at the entry point of plenty of hand-written
 * ELFs. What makes this stub itself is the cipher loop and the marker test in
 * the middle of it.
 */
static int stub_at(const struct kof_obj_ctx *ctx, uint64_t ep,
		   uint8_t *term_out, uint8_t *mark_out)
{
	uint8_t term;
	uint32_t i;

	if (!kof_in_obj(ep, STUB_LEN))
		return 0;
	term = kof_u8(ep + STUB_TERM_AT);
	for (i = 0; i < STUB_LEN; i++) {
		uint8_t got = kof_u8(ep + i);

		if (stub_want[i] == 0x100u) {
			if (got != term)
				return 0;
		} else if (stub_want[i] == 0x101u) {
			continue;               /* the marker: read, not checked */
		} else if (got != (uint8_t)stub_want[i]) {
			return 0;
		}
	}
	/*
	 * The call must be this stub's own GetPC.
	 *
	 * Its displacement is fixed in the listing, so the byte comparison above
	 * has already settled it - but the arithmetic is what the check MEANS,
	 * and doing it says so: the call has to land on the `pop ebx` that takes
	 * the address it pushed. A future build with a differently sized
	 * prologue would still be recognised here and rejected by bytes alone.
	 */
	{
		uint64_t after = ep + STUB_CALL_AT + 5u;
		int32_t  rel   = (int32_t)kof_u32(ep + STUB_CALL_AT + 1u);

		if (after + (int64_t)rel != ep + 2u)
			return 0;
	}
	*term_out = term;
	mark_out[0] = kof_u8(ep + STUB_MARK_AT);
	mark_out[1] = kof_u8(ep + STUB_MARK_AT + 1u);
	return 1;
}

KOF_DEFINE_UNPACK
{
	uint8_t buf[CHUNK], key[KEY_MAX];
	uint64_t ep, at, ct, end, produced;
	uint32_t keylen = 0, n = 0;
	uint8_t term, mark[2];

	/*
	 * WHERE THE STUB IS - two answers, one per kind of object this runs on.
	 * For an ELF the collector resolved the entry point to a file offset; for
	 * a formatless child the object IS the shellcode, so the stub is its
	 * first byte or this is not the format. Same reasoning as msf_xor_00.c.
	 */
	ep = ctx->entry_off;
	if (ep == KOF_NA || ep == KOF_BROKEN)
		ep = 0;
	if (!stub_at(ctx, ep, &term, mark))
		return;

	/* The key: from just past the call to the first terminator byte. */
	for (at = ep + STUB_KEY_AT; keylen < KEY_MAX && kof_in_obj(at, 1); at++) {
		uint8_t c = kof_u8(at);

		if (c == term)
			break;
		key[keylen++] = c;
	}
	if (!keylen || !kof_in_obj(at, 1) || kof_u8(at) != term)
		return;                 /* no terminator: not this format */
	ct = at + 1u;

	/* Named before anything is produced, so the child is labelled by this
	 * module and not by whichever spoke last - see the same note in ezuri.c. */
	kof_debug("MSF.xor.x86.key", keylen);

	/*
	 * WHERE THE PLAINTEXT ENDS, found before any of it is produced: at the
	 * two byte marker, read from the CIPHERTEXT before that byte would be
	 * decrypted, which is what the stub's own `cmp word [edi]` does. Running
	 * to the end of the object instead would append whatever follows the
	 * payload, XORed against a key it was never encrypted with.
	 */
	for (at = ct; kof_in_obj(at, 2); at++)
		if (kof_u8(at) == mark[0] && kof_u8(at + 1u) == mark[1])
			break;
	end = at;
	produced = end - ct;
	if (produced < PLAIN_MIN)
		return;

	for (at = ct; at < end; at++) {
		buf[n++] = (uint8_t)(kof_u8(at) ^
				     key[(uint32_t)((at - ct) % keylen)]);
		if (n == CHUNK) {
			if (!kof_emit(buf, n))
				return; /* the host has stopped taking bytes */
			n = 0;
		}
	}
	if (n && !kof_emit(buf, n))
		return;

	/*
	 * The handover is checked, for the reason ezuri.c gives: a packer's child
	 * is the whole of what the file was hiding, and reporting nothing after
	 * the host refused it would claim an unpacking that did not happen.
	 */
	if (!kof_child())
		kof_unp_broken(KOF_UNP_LIMIT);
}
