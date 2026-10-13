#ifndef KOFMOD_KOFDECODE_H
#define KOFMOD_KOFDECODE_H

/*
 * kofmod/kofdecode.h - asking the host to DECRYPT a range, by naming the cipher.
 *
 * WHERE THE ARITHMETIC LIVES. A module that undoes a packer's or an encoder's
 * cipher used to carry the loop: a repeating-key xor was written out in
 * msf_xor_00.c, again in msf_xor_x86_00.c, and a third time in the dword module,
 * each with its own chunking and its own idea of where a stream ends. A module
 * cannot link a library, so the host provides the loop and the module says WHICH
 * cipher and with WHAT - and keeps the part that is its own: recognising the
 * file, and reading the key, the offset and the length out of it. That is the
 * division bases/decoders is written on: a module is the logic that INVOKES a
 * decoder, and the decoder is in libuncoat, reached through the engine.
 *
 * A DESCRIPTOR, NOT A FAMILY OF CALLS. One struct and one enum, so a new cipher is
 * a new enumerator and not a new vtable slot, and a module built against the older
 * header keeps working. Positions are relative to the START OF THE RANGE a call is
 * given - a keystream does not know where in the file it began.
 *
 * READ-ONLY OVER THE OBJECT. Decrypting produces bytes; it never changes the
 * object it reads. The result goes where kunp_rcstruct_write sends bytes, or into
 * the caller's own buffer for a peek.
 */

#include <stdint.h>

enum kof_capsid_algo {
	KOF_CAPSID_NONE = 0,

	/*
	 * out[i] = in[i] ^ key[i % key_len]. A repeating key of any length; a
	 * constant dword is the same cipher with the four bytes of the constant, in
	 * the order they sit in memory.
	 */
	KOF_CAPSID_XOR_KEY = 1,

	/*
	 * out[i] = in[i] ^ (uint8_t)(k32 + i). The key is a counter - x86/countdown
	 * xors a byte with its own index - so nothing is carried in the stub, and
	 * because the keystream does not depend on the data the decode is the
	 * encode.
	 */
	KOF_CAPSID_XOR_COUNTER = 2,

	/*
	 * A DWORD AT A TIME WITH FEEDBACK: p = le32(in) ^ key, emit p, and then add p
	 * into the key before the next one - x86/jmp_call_additive. It stops after the
	 * first plaintext dword that is ZERO (which is emitted), or when the input or
	 * the output room runs out, so the length of the result is a fact about the
	 * data and not a number the caller can know first: ask for a peek with room
	 * enough and read how much came back.
	 */
	KOF_CAPSID_XOR_ADD32 = 3,

	/*
	 * A TEMPLATE WITH PLACEHOLDERS - x86/nonalpha and x86/nonupper. The input is
	 * the template; `k32` is the placeholder byte and `key`/`key_len` the
	 * subtrahends, in order. Each of the first key_len placeholders in the template
	 * becomes (placeholder - subtrahend), the rest of the template is untouched, and
	 * the output is the template's own length. A template with fewer placeholders
	 * than subtrahends simply uses what it has.
	 */
	KOF_CAPSID_PLACEHOLDER_SUB = 4,

	/*
	 * A CHAIN OF `sub eax, imm32` THAT PUSHES ITS RESULT - x86/alpha_mixed's
	 * dword-at-a-time form. The input is the INSTRUCTION STREAM, from the first
	 * `sub eax`; the host walks the three opcodes the chain is made of (sub, and,
	 * push, plus the stack bookkeeping), tracks eax, and every push after eax was
	 * zeroed by an `and` is one dword of the payload. The payload is built backwards
	 * on the stack, so the output is those dwords in REVERSE order. The walk stops
	 * at the first opcode that is not part of the chain.
	 */
	KOF_CAPSID_X86_SUB_CHAIN = 5,

	/* RC4, keyed by key/key_len (any length, at least 1). The keystream starts at
	 * the first byte of the input; running it over zeros yields the keystream. */
	KOF_CAPSID_RC4 = 6
};

struct kof_capsid {
	uint32_t        algo;           /* enum kof_capsid_algo */
	uint32_t        k32;            /* COUNTER: the first count; ADD32: the first key */
	const uint8_t  *key;            /* the key, or PLACEHOLDER_SUB's subtrahends */
	uint32_t        key_len;        /* at least 1 where there is a key */
	/*
	 * THE MOST BYTES THE CIPHER MAY PRODUCE, or 0 for as many as the range holds.
	 * A module bounds a cipher whose output is not the size of its input - the
	 * sub chain - so a long run of code cannot yield more than the module means
	 * to take. EVERY FIELD IS SET BY THE CALLER: a module is freestanding and
	 * cannot rely on a zeroed struct, so name this one even when it is 0.
	 */
	uint32_t        max_out;
};

#endif /* KOFMOD_KOFDECODE_H */
