/*
 * msf_x86_dword_00.c - msfvenom's four x86 encoders that carry their key inline.
 *
 * FOUR CODINGS IN ONE MODULE, and that is a decision worth defending because the
 * repo's other unpackers are one packer each. These four are one FAMILY: every
 * one of them is msfvenom's x86 shellcode wrapped by a fixed-length stub that
 * finds its own address, reads a key out of its own instruction stream, and
 * walks a counted body. They differ in the arithmetic and in nothing else -
 * which is the same relationship the NRV2B, NRV2E and LZMA codings have inside
 * upx_elf, and that module is one file for the same reason: the plumbing around
 * the transform is the whole of the module, and four copies of it would be four
 * places for one bug.
 *
 * What is NOT shared with them lives in one table below, one row per coding.
 *
 *
 * THE FOUR, AND HOW EACH FINDS ITS PARAMETERS
 *
 * Every number these stubs need is IN the stub - a count, a displacement, a key -
 * and every one of them is READ rather than assumed. The offsets below are the
 * positions of those fields in the instruction stream, not the values; msfvenom
 * varies the values per sample and would open one sample and misread the rest.
 *
 *   x86/fnstenv_mov          6a NN 59 d9 ee d9 74 24 f4 5b
 *                            81 73 DD KK KK KK KK 83 eb fc e2 f4
 *     fnstenv writes the FPU environment and offset 12 of it is the address of
 *     the last FPU instruction - the `fldz` at +3 - so `pop ebx` lands there and
 *     the body is at 3 + DD. NN dwords, each XORed with the constant KK.
 *
 *   x86/call4_dword_xor      33 c9 83 e9 NN e8 ff ff ff ff
 *                            c0 5e 81 76 DD KK KK KK KK 83 ee fc e2 f4
 *     `call $+4` with a -1 displacement returns into its own last byte, so the
 *     address it pushed is +10 and `pop esi` takes it. Body at 10 + DD, -NN
 *     dwords, constant XOR. The count is a NEGATIVE imm8 because the stub does
 *     `sub ecx, NN` to load it.
 *
 *   x86/countdown            6a NN 59 e8 ff ff ff ff c1 5e
 *                            30 4c 0e DD e2 fa
 *     The same GetPC, then `xor [esi+ecx+DD], cl` - the KEY IS THE COUNTER, so
 *     nothing has to be carried in the stub at all. NN bytes, counted down, and
 *     because a byte is XORed with its own index the decode is the encode.
 *
 *   x86/jmp_call_additive    fc bb KK KK KK KK eb 0c 5e 56
 *                            31 1e ad 01 c3 85 c0 75 f7 c3 e8 rr rr rr rr
 *     The one with feedback: xor the dword, then ADD the plaintext to the key
 *     before the next one, and stop when a plaintext dword comes out zero. The
 *     body is where the trailing call returns to, so it is read from that call's
 *     displacement rather than counted from the stub's length.
 *
 *
 * WHY THE PLAINTEXT IS NOT CHECKED AGAINST ANYTHING
 *
 * It is not, and it does not need to be: each stub is thirteen to twenty-five
 * bytes matched exactly, which is a far narrower filter than any test on the
 * output would be. The four were verified against each other instead, which is
 * the strongest check available here - the same msfvenom payload encoded four
 * ways decodes to four identical byte strings, and it does, byte for byte, on
 * the samples in samples/msfvenom-encr. A transform with a wrong offset or a
 * wrong key does not agree with three others by accident.
 */

#include <kofmod/kofsig.h>
#include <kofshared/msf_elf32.h>

KOF_ANALYZE_STEP(KOF_ANALYZE_DECRYPT);

/*
 * ELF and the formatless children both, for the reason msf_xor_00.c gives: a
 * payload these produce may itself be wrapped again, and the layer after the
 * first has no header for a format target to match.
 */
KOF_TARGET_FORMAT(KOF_FMT_ELF | KOF_FMT_PE | KOF_FMT_UNKNOWN);
KOF_TARGET_CONTENT("Dword");

/* The family this decodes, so a heuristic predicting Meterp routes here first. */
KOF_TARGET_NAME(KOF_MALTYPE_TROJAN, "Meterp");

/* Below this the plaintext cannot be a payload; the x86 stager measured here is
 * 123 bytes. */
#define PLAIN_MIN   32u

/* How much is decrypted before it is handed over. */
#define CHUNK       1024u

/* No body may be longer than this. The count byte is at most 255 dwords, so the
 * bound is generous and exists only so an absurd displacement cannot make the
 * loop run past what the object holds - kof_in_obj is what actually stops it. */
#define BODY_MAX    (256u * 4u)

/*
 * Which coding, and it is only used to pick the arithmetic below. Named rather
 * than numbered because the log line carries it and a number there would be a
 * thing to look up.
 */
enum {
	C_FNSTENV = 1,
	C_CALL4   = 2,
	C_COUNTDN = 3,
	C_ADDITIVE = 4
};

/*
 * The fixed bytes of each stub, 0x100 marking a byte that varies - a count, a
 * displacement or a key byte. Read as a run of exact comparisons; the variable
 * positions are picked out afterwards by the offsets each row carries.
 */
static const uint16_t stub_pat[] = {
	/* --- C_FNSTENV, 24 --- */
	0x6a,0x100,                    /* push NN                       */
	0x59,                          /* pop ecx                       */
	0xd9,0xee,                     /* fldz                          */
	0xd9,0x74,0x24,0xf4,           /* fnstenv [esp-0xc]             */
	0x5b,                          /* pop ebx                       */
	0x81,0x73,0x100,               /* xor dword [ebx+DD], ...       */
	0x100,0x100,0x100,0x100,       /*   ... KK KK KK KK             */
	0x83,0xeb,0xfc,                /* sub ebx, -4                   */
	0xe2,0xf4                      /* loop                          */
	,
	/* --- C_CALL4, 24 --- */
	0x33,0xc9,                     /* xor ecx, ecx                  */
	0x83,0xe9,0x100,               /* sub ecx, NN                   */
	0xe8,0xff,0xff,0xff,0xff,      /* call $+4                      */
	0xc0,                          /* (the byte the call returns into) */
	0x5e,                          /* pop esi                       */
	0x81,0x76,0x100,               /* xor dword [esi+DD], ...       */
	0x100,0x100,0x100,0x100,
	0x83,0xee,0xfc,                /* sub esi, -4                   */
	0xe2,0xf4                      /* loop                          */
	,
	/* --- C_COUNTDN, 16 --- */
	0x6a,0x100,                    /* push NN                       */
	0x59,                          /* pop ecx                       */
	0xe8,0xff,0xff,0xff,0xff,      /* call $+4                      */
	0xc1,                          /* (returned into)               */
	0x5e,                          /* pop esi                       */
	0x30,0x4c,0x0e,0x100,          /* xor [esi+ecx+DD], cl          */
	0xe2,0xfa                      /* loop                          */
	,
	/* --- C_ADDITIVE, 21 --- */
	0xfc,                          /* cld                           */
	0xbb,0x100,0x100,0x100,0x100,  /* mov ebx, KK KK KK KK          */
	0xeb,0x0c,                     /* jmp +0xc                      */
	0x5e,                          /* pop esi                       */
	0x56,                          /* push esi                      */
	0x31,0x1e,                     /* xor [esi], ebx                */
	0xad,                          /* lodsd                         */
	0x01,0xc3,                     /* add ebx, eax                  */
	0x85,0xc0,                     /* test eax, eax                 */
	0x75,0xf7,                     /* jnz                           */
	0xc3,                          /* ret                           */
	0xe8                           /* call (its rel32 is read)      */
};

/*
 * One row per coding: the pattern, its length, and where inside it each field
 * sits. A field this coding does not have is 0 and is never read - which of them
 * are read is decided by `code`, so a zero here is not a value that could be
 * used by mistake.
 */
/*
 * An INDEX into stub_pat, not a pointer into it.
 *
 * A pointer would need a relocation, a relocation puts the table in .data, and a
 * module is not allowed writable data at all - the build refuses one, which is
 * how this was caught. The patterns are therefore one flat array and each row
 * says where in it to look.
 */
static const struct {
	uint32_t        at;         /* where in stub_pat this row starts  */
	uint32_t        n;
	uint32_t        code;
	uint32_t        cnt_at;     /* the count imm8                     */
	uint32_t        disp_at;    /* the displacement imm8              */
	uint32_t        key_at;     /* the imm32 key                      */
	uint32_t        getpc;      /* what the GetPC leaves, from +0     */
} coding[] = {
	{  0u, 22u, C_FNSTENV,  1u, 12u, 13u,  3u },
	{ 22u, 24u, C_CALL4,    4u, 14u, 15u, 10u },
	{ 46u, 16u, C_COUNTDN,  1u, 13u,  0u,  8u },
	{ 62u, 21u, C_ADDITIVE, 0u,  0u,  2u,  0u }
};

/*
 * The rows have to add up to the array, or one of them is reading another's
 * bytes. A build-time check, and it earned its place immediately: the first
 * version of the table above had two lengths and two key offsets wrong, and this
 * is what said so - rather than a module that compiled and decoded noise.
 */
typedef char coding_rows_cover_stub_pat[
	(62u + 21u) == (sizeof stub_pat / sizeof stub_pat[0]) ? 1 : -1];

#define N_CODING (sizeof coding / sizeof coding[0])

/* Does the run of fixed bytes at `ep` match row `c`? */
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

KOF_DEFINE_UNPACK
{
	uint8_t keyb[4];
	uint64_t ep, body, call_len;
	uint32_t c, found = N_CODING, cnt = 0, key = 0;
	struct kof_capsid capsid;

	/*
	 * WHERE THE STUB IS: the resolved entry point for an ELF, offset zero for
	 * a formatless child, which IS the shellcode. See msf_xor_00.c.
	 */
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

	/*
	 * The body's address, and each coding says it differently.
	 *
	 * The three counted ones name it as a displacement from whatever their
	 * GetPC left behind, so it is that plus the displacement the stub
	 * carries. The additive one does not count at all: its body is simply
	 * where its trailing call returns to, which is the byte after the call.
	 */
	if (coding[found].code == C_ADDITIVE) {
		uint64_t call_at = ep + coding[found].n - 1u;   /* the 0xe8 */

		if (!kof_in_obj(call_at, 5))
			return;
		body = call_at + 5u;
		key  = kof_u32(ep + coding[found].key_at);
	} else {
		uint8_t disp = kof_u8(ep + coding[found].disp_at);

		body = ep + coding[found].getpc + disp;
		/*
		 * COUNTDOWN IS ONE FURTHER ON, because its address includes the
		 * counter and the counter never reaches zero: the last iteration
		 * runs with ecx == 1, so the lowest byte it touches is
		 * esi + 1 + DD. The other two index from zero.
		 */
		if (coding[found].code == C_COUNTDN)
			body += 1u;
		cnt  = kof_u8(ep + coding[found].cnt_at);
		/*
		 * call4 loads its count with `sub ecx, imm8`, so the byte in the
		 * stub is the NEGATIVE of it. Taken as a signed value and negated
		 * rather than subtracted from 256, because that is what the
		 * instruction does and the two differ at zero.
		 */
		if (coding[found].code == C_CALL4)
			cnt = (uint32_t)(-(int32_t)(int8_t)cnt) & 0xffu;
		if (!cnt)
			return;
		if (coding[found].key_at)
			key = kof_u32(ep + coding[found].key_at);
	}
	if (body <= ep || !kof_in_obj(body, PLAIN_MIN))
		return;

	/* Which coding opened it, before anything is produced - so the object is
	 * labelled by this module rather than by whichever spoke last. */
	kof_debug("MSF.x86.coding", coding[found].code);

	/*
	 * THE PAYLOAD LENGTH, computed before a byte of it is emitted, so the
	 * ELF32 header that goes in front carries the right p_filesz - see
	 * msf_elf32.h. The bounds each coding needs are checked here too, so a
	 * header is never emitted for a payload that then turns out not to fit.
	 * The additive coding has no count in the stub - it stops at the first
	 * zero plaintext dword - so its length is found by a pre-pass that runs
	 * the same feedback without emitting, on a copy of the key.
	 */
	/*
	 * THE CIPHER IS THE HOST'S - see kofmod/kofdecode.h. Each coding is a
	 * descriptor over the body: a constant dword is a four-byte repeating key, the
	 * countdown is a counter keystream, the additive one is the feedback cipher.
	 * What stays here is the part that is this module's: which stub it is, and
	 * the key, the count and the body's address read out of it.
	 */
	keyb[0] = (uint8_t)key;
	keyb[1] = (uint8_t)(key >> 8);
	keyb[2] = (uint8_t)(key >> 16);
	keyb[3] = (uint8_t)(key >> 24);
	capsid.k32 = 0;
	capsid.key = 0;
	capsid.key_len = 0;
	capsid.max_out = 0;
	if (coding[found].code == C_COUNTDN) {
		if (cnt > BODY_MAX || !kof_in_obj(body, cnt))
			return;
		/* Byte k is xored with k + 1: the counter, counted down by the stub
		 * and read back up here. */
		capsid.algo = KOF_CAPSID_XOR_COUNTER;
		capsid.k32 = 1u;
		call_len = cnt;
	} else if (coding[found].code == C_ADDITIVE) {
		uint8_t scratch[BODY_MAX];

		capsid.algo = KOF_CAPSID_XOR_ADD32;
		capsid.k32 = key;
		/* No count in the stub - it stops at the first zero plaintext dword -
		 * so the length is what the cipher yields when it is run. */
		call_len = kunp_decrypt_peek(&capsid, body, BODY_MAX, scratch,
					     BODY_MAX);
	} else {
		if (cnt > BODY_MAX / 4u ||
		    !kof_in_obj(body, (uint64_t)cnt * 4u))
			return;
		capsid.algo = KOF_CAPSID_XOR_KEY;
		capsid.key = keyb;
		capsid.key_len = 4u;
		call_len = (uint64_t)cnt * 4u;
	}
	if (call_len < PLAIN_MIN)
		return;
	if (!msf_emit_hdr(ctx, (uint32_t)call_len))
		return;
	if (!kunp_decrypt(&capsid, body, coding[found].code == C_ADDITIVE
				      ? (uint64_t)BODY_MAX : call_len))
		return;                 /* the host has stopped taking bytes */

	kunp_rcstruct_supersedes();
	if (!kunp_rcstruct_done())
		kunp_rcstruct_broken(KOF_UNP_LIMIT);
}
