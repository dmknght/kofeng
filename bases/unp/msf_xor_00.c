/*
 * msf_xor_00.c - peel one layer of Metasploit's self-describing XOR wrapper.
 *
 * msfvenom can wrap an ELF payload in an encoder whose whole decryptor is
 * forty-six bytes at the entry point. The wrapper carries its own key, so
 * nothing outside the file is needed to undo it - which makes it the one class
 * of "encrypted" payload a static unpacker can open completely, with no
 * interpreter and no guessing.
 *
 *
 * THE FORMAT, READ OUT OF THE STUB ITSELF
 *
 * At the entry point, byte for byte:
 *
 *     eb 27              jmp   +0x27          -> the call below
 *     5b                 pop   rbx            -> rbx = the return address
 *     53 5f              push  rbx; pop rdi   -> rdi = the same
 *     b0 TT              mov   al, TT         -> TT terminates the key
 *     fc                 cld
 *     ae                 scasb                -> walk rdi to the first TT
 *     75 fd              jne   -3
 *     57 59              push  rdi; pop rcx   -> rcx = past it: the ciphertext
 *     53 5e              push  rbx; pop rsi   -> rsi = back to the key
 *     8a 06              mov   al, [rsi]
 *     30 07              xor   [rdi], al      -> the whole cipher, one byte
 *     48 ff c7           inc   rdi
 *     48 ff c6           inc   rsi
 *     66 81 3f LL HH     cmp   word [rdi], HHLL    -> the end marker
 *     74 07              je    +7             -> done: jmp rcx
 *     80 3e TT           cmp   byte [rsi], TT -> key exhausted?
 *     75 ea              jne   -0x16          -> no: next byte
 *     eb e6              jmp   -0x1a          -> yes: rewind rsi to rbx
 *     ff e1              jmp   rcx            -> run what was decrypted
 *     e8 d4 ff ff ff     call  -0x2c          -> pushes the key's address
 *     <key bytes> TT <ciphertext> LL HH
 *
 * So the layout is fully determined by three things the file states about
 * itself: the terminator byte in the `mov al` at entry+5, the two byte end
 * marker in the `cmp word` at entry+28, and the return address the `call`
 * pushes - which is simply the byte after the call, so it need not be computed
 * from the displacement at all. The displacement IS checked, because it is what
 * proves the call is this stub's GetPC and not some other call that happens to
 * sit there: it must land back on the `pop rbx` at entry+2.
 *
 * BOTH the terminator and the marker are chosen per sample, and that is the
 * thing to get right rather than to hard code. Measured on four wrapped
 * samples: terminators cf, 77, e9, 95 and markers e0 22, a8 e4, bc 8d, 24 45 -
 * no two alike, because each has to be a byte (or pair) the payload does not
 * contain, so the packer picks them from what the payload leaves free. A module
 * that spelled one sample's marker as a constant would open that sample and
 * silently decrypt the other three past their real end.
 *
 * A repeating-key XOR with the key in the file is not encryption in any useful
 * sense, and the samples measured here carry a ONE byte key. That is not a
 * weakness of the reading below - the loop above is the whole algorithm, and it
 * is the same for a key of any length.
 *
 *
 * WHY THIS PEELS ONE LAYER AND NOT ALL OF THEM
 *
 * msfvenom applies the encoder as many times as asked, and the samples here are
 * wrapped three deep: undoing one layer yields another stub with another key.
 * This module does not loop. It emits the plaintext as a CHILD, and the engine
 * scans that child as an object in its own right - which brings it back here,
 * with the next layer's own bounds read from the next layer's own bytes.
 *
 * That is the module ABI's rule rather than a preference: a module cannot call
 * another, and it hands work over by producing children. It also gets the
 * accounting right for free - three layers become three objects, each with its
 * own regions and its own signature pass, and the depth limit that bounds every
 * other packer bounds this one too. A loop in here would produce one object and
 * hide the two the file actually contains.
 *
 *
 * WHAT THE PLAINTEXT IS NOT
 *
 * The decrypted bytes are shellcode, not an ELF. They begin at offset 0 of the
 * child with no header, so the child identifies as no format - which is correct
 * and is what an unwrapped payload is. The signatures that match a stager match
 * bytes, and bytes are what this produces.
 */

#include <kofmod/kofsig.h>

KOF_UNPACK_KIND(KOF_UNP_PACKER);

/*
 * ELF AND FORMATLESS, because the second layer has no header.
 *
 * The first layer is an ELF: msfvenom writes a template with the stub at the
 * entry point. What that layer decrypts to is shellcode - the next stub, and
 * nothing in front of it - so the child identifies as no format at all. Naming
 * only ELF would peel exactly one layer of a sample wrapped three deep and
 * report the other two as a formatless object nobody looked at, which is what
 * this module did before the second name was added.
 *
 * No format header is included, and that is required rather than incidental:
 * kof_elf() casts ctx->file_header, a formatless object has none, and the ABI
 * allows more than one target only for a module that never casts. The two facts
 * this needs - the format and the entry offset - are on the context itself.
 */
KOF_TARGET_FORMAT(KOF_FMT_ELF | KOF_FMT_UNKNOWN);

/*
 * THE FAMILY THIS DECODES, so the engine can try it first.
 *
 * An unpacker reports no findings, so this names nothing on its own - it is
 * unread by everything except the family-first routing in scan.c. A heuristic
 * that predicts "Meterp" (see bases/heur/shellcode_00.c) makes the engine run
 * the unpackers of family Meterp - this one - before the rest. On an object that
 * really is a Meterp payload that is the fast path; on one that is not, this
 * declines like any other unpacker and the general pass runs.
 */
KOF_TARGET_NAME(KOF_MALTYPE_TROJAN, "Meterp");

/*
 * NO ARCHITECTURE IS DECLARED, and it is tempting to declare one: the stub is
 * amd64 machine code and on any other architecture these bytes are data that
 * happens to look like it.
 *
 * It cannot be declared, because the objects after the first have no
 * architecture to compare against. A formatless child carries KOF_ARCH_ANY, the
 * host's unpacker loop rules out any module whose arch_mask does not hold the
 * object's arch, and a declared amd64 would therefore skip every layer but the
 * outermost - the same failure the single format target caused.
 *
 * Nothing is lost by leaving it off. Forty-six bytes matched exactly is a far
 * narrower filter than an architecture is, and it is checked on the first byte
 * that differs.
 */

/*
 * Where the pieces sit relative to the entry point. Named rather than spelled
 * as numbers at the use site, because every one of them is a fact about the
 * listing above and a reader has to be able to check them against it.
 */
#define STUB_TERM_AT   6u              /* the imm8 of `mov al, TT`          */
#define STUB_MARK_AT   28u             /* the imm16 of `cmp word [rdi], ..` */
#define STUB_CALL_AT   41u             /* the `e8` of the GetPC call        */
#define STUB_KEY_AT    46u             /* one past it: what the call pushes */
#define STUB_LEN       STUB_KEY_AT

/* The longest key this will follow. The scasb in the stub has no bound at all,
 * but a "key" that runs for kilobytes is a file whose terminator byte never
 * appears - which is not this format, and following it would decrypt an object
 * against noise. */
#define KEY_MAX        256u

/* Below this the plaintext cannot be a payload, and emitting it would cost a
 * scan a child made of nothing. The smallest thing msfvenom will wrap is a
 * stager, and the ones measured here are 132 bytes. */
#define PLAIN_MIN      32u

/* How much is decrypted before it is handed over, so a large payload costs a
 * fixed amount of stack. */
#define CHUNK          1024u

/*
 * The fixed bytes of the stub, with 0x100 standing for "the terminator,
 * whatever this sample chose" - it appears twice, once in the `mov al` and once
 * in the `cmp byte [rsi]`, and the two must agree - and 0x101 for the two marker
 * bytes, which are whatever this sample chose and are not constrained to
 * anything, so nothing is asserted about them here.
 *
 * At file scope because it is checked against TWO things: the object, through
 * the byte accessors, and a buffer of plaintext this module has just produced.
 * One table, so the two questions cannot come to different answers.
 */
static const uint16_t stub_want[STUB_KEY_AT] = {
		0xeb,0x27,                     /* jmp +0x27                  */
		0x5b,0x53,0x5f,                /* pop rbx; push rbx; pop rdi */
		0xb0,0x100,                    /* mov al, TT                 */
		0xfc,                          /* cld                        */
		0xae,0x75,0xfd,                /* scasb; jne -3              */
		0x57,0x59,                     /* push rdi; pop rcx          */
		0x53,0x5e,                     /* push rbx; pop rsi          */
		0x8a,0x06,                     /* mov al, [rsi]              */
		0x30,0x07,                     /* xor [rdi], al              */
		0x48,0xff,0xc7,                /* inc rdi                    */
		0x48,0xff,0xc6,                /* inc rsi                    */
		0x66,0x81,0x3f,0x101,0x101,    /* cmp word [rdi], HHLL       */
		0x74,0x07,                     /* je +7                      */
		0x80,0x3e,0x100,               /* cmp byte [rsi], TT         */
		0x75,0xea,                     /* jne -0x16                  */
		0xeb,0xe6,                     /* jmp -0x1a                  */
		0xff,0xe1,                     /* jmp rcx                    */
		0xe8,0xd4,0xff,0xff,0xff       /* call -0x2c                 */
	};

/*
 * Is the stub at `ep` this stub? Every byte of the fixed part is checked.
 *
 * The whole prologue rather than a shorter prefix, because the prefix that
 * would identify it - a jmp, two pops, a mov - is ordinary code that appears at
 * the entry point of plenty of hand-written ELFs. What makes this stub itself is
 * the cipher loop in the middle and the end marker inside it, and those are the
 * bytes worth insisting on.
 */
static int stub_at(const struct kof_obj_ctx *ctx, uint64_t ep,
		   uint8_t *term_out, uint8_t *mark_out)
{
	static const uint16_t *want = stub_want;
	uint8_t term;
	uint32_t i;

	if (!kof_in_obj(ep, STUB_LEN))
		return 0;
	term = kof_u8(ep + STUB_TERM_AT);
	for (i = 0; i < STUB_KEY_AT; i++) {
		uint8_t got = kof_u8(ep + i);

		if (want[i] == 0x100u) {
			if (got != term)
				return 0;
		} else if (want[i] == 0x101u) {
			continue;               /* the marker: read, not checked */
		} else if (got != (uint8_t)want[i]) {
			return 0;
		}
	}
	/*
	 * The call must be this stub's own GetPC.
	 *
	 * Its displacement is fixed in the listing, so comparing the bytes above
	 * already settles it - but the arithmetic is what the check MEANS, and
	 * doing it here says so: the call has to land on the `pop rbx` that
	 * takes the address it pushed. A future build with a differently sized
	 * prologue would still be recognised by this and rejected by a byte
	 * comparison alone.
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

/*
 * Is the plaintext this module just produced another wrapper?
 *
 * The same table as stub_at, against bytes rather than against the object. What
 * it decides is whether the layer is the LAST one, which is the only thing the
 * header below is attached to - see the note there.
 */
static int stub_in_buf(const uint8_t *p, uint32_t n)
{
	uint8_t term;
	uint32_t i;

	if (n < STUB_KEY_AT)
		return 0;
	term = p[STUB_TERM_AT];
	for (i = 0; i < STUB_KEY_AT; i++) {
		if (stub_want[i] == 0x100u) {
			if (p[i] != term)
				return 0;
		} else if (stub_want[i] == 0x101u) {
			continue;
		} else if (p[i] != (uint8_t)stub_want[i]) {
			return 0;
		}
	}
	return 1;
}

/*
 * THE HEADER msfvenom WOULD HAVE WRITTEN, PUT BACK IN FRONT OF THE PAYLOAD.
 *
 * WHY THIS EXISTS. The payload that comes out of the last layer is machine code
 * and nothing else, so the object had no format - and a signature written for
 * it therefore could not use an ELF region. The alternative was to let rules
 * name two formats and branch on which one they got, and that is worse for the
 * reason the build already gives for keeping one format per module: the branch
 * is N places that can forget, against one that can be tested. Reattaching the
 * header moves the work to the one place that knows the payload is an ELF
 * payload - here.
 *
 * WHAT IS BEING CLAIMED, and it is narrow. msfvenom does not compile these; it
 * pastes the payload into a fixed template, and the template is these 120 bytes
 * with two lengths patched. So this is not an invention: it is the same file
 * with the encoder undone, and `cleartext` in the sample set is the reference -
 * a payload built with no encoder at all is byte for byte this layout.
 *
 * WHAT IS NOT CLAIMED: that a file like this was ever on disk. It was not. The
 * object is what the packer's own loader would have run, expressed in the format
 * its outermost layer was, and the viewer shows it as a child of that layer
 * rather than as anything found.
 *
 * ONLY THE LAST LAYER GETS ONE. A sample encoded twenty times would otherwise
 * carry twenty reconstructed headers, nineteen of them wrapping a decryptor
 * rather than a payload - work and objects for nothing. The intermediate layers
 * stay formatless, which is what they are.
 */
#define ELF_HDR_N   0x78u
#define ELF_BASE    0x400000ull

static void put64(uint8_t *p, uint64_t v)
{
	unsigned i;

	for (i = 0; i < 8; i++)
		p[i] = (uint8_t)(v >> (i * 8));
}

static int emit_elf_hdr(const struct kof_obj_ctx *ctx, uint64_t payload_n)
{
	uint8_t h[ELF_HDR_N];
	uint8_t *ph = h + 0x40;
	uint64_t total = ELF_HDR_N + payload_n;
	unsigned k;

	/* Zeroed by hand: a module links against nothing, so there is no
	 * memset here to call. */
	for (k = 0; k < ELF_HDR_N; k++)
		h[k] = 0;
	h[0] = 0x7f; h[1] = 'E'; h[2] = 'L'; h[3] = 'F';
	h[4] = 2;                       /* ELFCLASS64                       */
	h[5] = 1;                       /* ELFDATA2LSB                      */
	h[6] = 1;                       /* EV_CURRENT                       */
	h[0x10] = 2;                    /* ET_EXEC                          */
	h[0x12] = 0x3e;                 /* EM_X86_64                        */
	h[0x14] = 1;                    /* e_version                        */
	put64(h + 0x18, ELF_BASE + ELF_HDR_N);   /* e_entry: the payload    */
	put64(h + 0x20, 0x40);          /* e_phoff                          */
	/* e_shoff stays zero: the template has no section table, and neither
	 * has any sample measured. */
	h[0x34] = 0x40;                 /* e_ehsize                         */
	h[0x36] = 0x38;                 /* e_phentsize                      */
	h[0x38] = 1;                    /* e_phnum                          */

	ph[0] = 1;                      /* PT_LOAD                          */
	ph[4] = 7;                      /* RWX, which is what the template   */
					/* asks for - the payload writes to  */
					/* itself                            */
	put64(ph + 0x08, 0);            /* p_offset                         */
	put64(ph + 0x10, ELF_BASE);     /* p_vaddr                          */
	put64(ph + 0x18, ELF_BASE);     /* p_paddr                          */
	put64(ph + 0x20, total);        /* p_filesz                         */
	/*
	 * p_memsz = p_filesz. The template pads it - `cleartext` asks for 680
	 * bytes of image for 250 of file - and the padding is a constant of the
	 * template rather than anything derived from the payload, so copying the
	 * number would be inventing one. Against that sample this reconstruction
	 * differs in these eight bytes and in nothing else.
	 */
	put64(ph + 0x28, total);        /* p_memsz                          */
	put64(ph + 0x30, 0x1000);       /* p_align                          */
	return kof_emit(h, ELF_HDR_N);
}

KOF_DEFINE_UNPACK
{
	uint8_t buf[CHUNK], key[KEY_MAX];
	uint64_t ep, at, ct, end, produced = 0;
	uint32_t keylen = 0, n = 0, first;
	uint8_t term, mark[2];

	/*
	 * WHERE THE STUB IS, and it is a different answer for the two kinds of
	 * object this runs on.
	 *
	 * For an ELF the collector has already resolved the entry point to a
	 * file offset, and that is where msfvenom's template puts the stub.
	 * Reading e_entry and subtracting a load address here would be a second
	 * answer to a question the parse has answered, and the two would
	 * disagree on exactly the objects that matter - the ones whose headers
	 * are odd.
	 *
	 * For a formatless object there is no entry point to resolve: the object
	 * IS the shellcode, so the stub is its first byte or the object is not
	 * this format. Falling back to zero rather than refusing is what lets
	 * the layers after the first be opened by the same code.
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

	/*
	 * Name this module before it produces anything - see the same note in
	 * ezuri.c. Without it the child is labelled with whatever module spoke
	 * last, which on a nested sample is this module's own previous layer and
	 * reads as if one object had been unpacked twice.
	 */
	kof_debug("MSF.xor.key", keylen);

	/*
	 * WHERE THE PLAINTEXT ENDS, found before any of it is produced.
	 *
	 * It ends where the stub's own loop ends: at the two byte marker, not at
	 * the end of the object. Stopping at the marker matters because the
	 * wrapper puts nothing after it - so a run to the end would append
	 * whatever the file carries past the payload, XORed against a key it was
	 * never encrypted with. The marker is read from the CIPHERTEXT, before
	 * the XOR, which is what the stub does: `cmp word [rdi]` runs on the byte
	 * it is about to decrypt.
	 *
	 * Found in its own pass rather than as the loop runs, because the header
	 * this may put in front carries the length and has to be written first.
	 * The pass is a byte comparison over the ciphertext and costs nothing
	 * against the decryption that follows it.
	 */
	for (at = ct; kof_in_obj(at, 2); at++)
		if (kof_u8(at) == mark[0] && kof_u8(at + 1u) == mark[1])
			break;
	end = at;
	produced = end - ct;
	if (produced < PLAIN_MIN)
		return;

	/*
	 * The first chunk, decrypted but not yet handed over: what it holds
	 * decides whether a header goes in front of it.
	 */
	first = produced < CHUNK ? (uint32_t)produced : CHUNK;
	for (n = 0; n < first; n++)
		buf[n] = (uint8_t)(kof_u8(ct + n) ^ key[n % keylen]);

	/*
	 * A layer that decrypts to another stub is a decryptor, not a payload,
	 * and stays formatless. Only the last one is given its header back - see
	 * emit_elf_hdr.
	 */
	if (!stub_in_buf(buf, n) && !emit_elf_hdr(ctx, produced))
		return;
	if (!kof_emit(buf, n))
		return;
	/* Handed over, so the buffer starts again - without this the tail flush
	 * below emitted the first chunk a second time. */
	at = ct + n;
	n = 0;
	for (; at < end; at++) {
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
	 * The handover is checked, for the reason ezuri.c gives: a packer's
	 * child is the whole of what the file was hiding, and reporting nothing
	 * after the host refused it would claim an unpacking that did not
	 * happen.
	 */
	if (!kof_child())
		kof_unp_broken(KOF_UNP_LIMIT);
}
