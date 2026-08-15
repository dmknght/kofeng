/*
 * custom_stub_demo.c - a decoder that lives ENTIRELY in the signature.
 *
 * In tests/sigs rather than bases/unp because it detects nothing: there is no
 * malware that uses this coding. It is here to hold one claim about the module ABI
 * true - that a signature can carry its own unpacker - so that the claim is checked
 * by the build rather than believed.
 *
 * Every other unpacker here names a coding the engine already has and asks the host
 * to run it: kof_unpack_at(KOF_UNP_LZMA2, ...) and the decoder is C compiled into
 * libkofeng. That works because inflate, LZMA, LZMA2 and NRV2 are formats - few,
 * stable, and worth having once.
 *
 * A packer written for one family is none of those things. It is a thirty line
 * loop somebody invented, it appears in a handful of samples, and by the time an
 * engine release could carry it the campaign is over. Waiting for a release to
 * read it is the wrong shape of answer.
 *
 * So this one carries its own decoder. The bytes are read with kof_u8, decoded by
 * arithmetic in this file, and handed over with kof_emit - no host support of any
 * kind, and nothing about it that a later build has to grow. It exists to establish
 * that the module ABI is enough to do that, because "signatures can only match
 * strings" would be a real limit and it is not this one.
 *
 *
 * WHAT A MODULE MAY DO, AND WHAT IT MAY NOT
 *
 * It may compute. There is no restriction on arithmetic, loops or local buffers -
 * the build refuses relocations and mutable globals, not thinking.
 *
 * It may not allocate, and it may not keep state between calls. Both follow from
 * the same rule: a module is a position independent blob with no writable data, so
 * a scratch buffer is a local array and its size is the stack the host gives. That
 * is what shapes a decoder written here - it must stream, in bounded pieces,
 * because it has nowhere to put a whole output.
 *
 *
 * THE CODING, WHICH IS DELIBERATELY A TOY
 *
 * A rolling XOR and a run length escape, which is what a hand written stub usually
 * amounts to:
 *
 *     ESC n b     n copies of b
 *     x           the literal x, XORed with a key that advances each byte
 *
 * The point is the mechanism, not this coding. Anything expressible in C is
 * expressible here.
 */

#include <kofmod/kofsig.h>
#include <kofmod/elf.h>

KOF_TARGET_FORMAT(KOF_FMT_ELF);

/* The stub's marker. A real one would be a byte pattern from the sample. */
KOF_DEFINE_HEXSTR(stub_magic, "4B 4F 46 53 54 55 42 30");   /* KOFSTUB0 */

#define ESC        0xa5u
#define KEY_INIT   0x5au
#define KEY_STEP   0x1bu

/*
 * Emitted in pieces, because there is nowhere to put a whole one.
 *
 * 512 bytes of stack rather than 64KB: a module runs on whatever stack the host
 * was on when it called, and being modest about that is the difference between a
 * decoder that works and one that works until the tree is deep.
 */
#define CHUNK 512u

KOF_DEFINE_UNPACK
{
	uint64_t at, end, produced = 0;
	uint8_t out[CHUNK];
	uint32_t n = 0;
	uint8_t key = KEY_INIT;

	/*
	 * Where the payload starts, found by the marker rather than by an offset.
	 * A stub that moves is the ordinary case, and searching for its own magic
	 * is what makes one module cover a family instead of one build of it.
	 */
	at = kof_find_str_where(0, ctx->obj_size, stub_magic);
	if (at == KOF_BROKEN)
		return;
	at += 8u;                        /* past the marker */
	end = ctx->obj_size;

	while (at < end) {
		uint8_t c = kof_u8(at++);

		if (c == ESC) {
			uint32_t run, k;
			uint8_t val;

			if (at + 2u > end)
				break;
			run = kof_u8(at++);
			val = kof_u8(at++);
			for (k = 0; k < run; k++) {
				out[n++] = val;
				if (n == CHUNK) {
					if (!kof_emit(out, n))
						return;
					produced += n;
					n = 0;
				}
			}
			continue;
		}

		out[n++] = (uint8_t)(c ^ key);
		key = (uint8_t)(key + KEY_STEP);
		if (n == CHUNK) {
			if (!kof_emit(out, n))
				return;
			produced += n;
			n = 0;
		}
	}

	if (n) {
		if (!kof_emit(out, n))
			return;
		produced += n;
	}

	kof_debug("CustomStub.bytes", produced);
	if (produced)
		kof_child();
}
