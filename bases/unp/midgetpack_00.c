/*
 * midgetpack_00.c - identify midgetpack, and say why it cannot be opened.
 *
 * THIS MODULE RECOVERS NOTHING, ON PURPOSE. That is unusual enough to be the
 * first thing said about it, and the reason is a fact about the packer rather
 * than a limit of this engine: midgetpack derives its key from a password typed
 * at runtime, so the key is not in the file and no reader of the file can
 * produce it. What the module does instead is name the packer and record
 * KOF_UNP_ENCRYPTED, which is the value the ABI has for exactly this - content
 * that is encrypted with no key available, a reason that "never closes" the way
 * an unsupported coding does.
 *
 *
 * HOW THE PASSWORD WAS ESTABLISHED, RATHER THAN ASSUMED
 *
 * Running a sample under the emulator, the guest wrote to its standard error:
 *
 *     starting stub ...
 *     Password:
 *
 * and then read its standard input sixty-one times. The stub carries the SHA-256
 * initialisation constant (0x6a09e667) and none of the constants that would name
 * another key schedule - no TEA delta, no ChaCha sigma, no AES S-box - so the
 * key is a hash of what it reads. Feeding it an empty password (one newline,
 * then end of file) got past the prompt and produced nothing: the run wrote two
 * pages of scratch and stalled, which is what a wrong key looks like.
 *
 * The stub is also byte-identical across all two hundred samples measured, so
 * there is nowhere for per-sample key material to hide in it, and the payload
 * segment differs in every sample as ciphertext should. A key that is neither in
 * the stub nor in the payload is not in the file.
 *
 *
 * WHY IDENTIFYING IT IS STILL WORTH A MODULE
 *
 * Without this, a midgetpack sample reaches the end of every module, gets
 * nothing from any of them, and is reported by the emulator's gate as "Unknown
 * packer" - which is wrong twice: the packer is known, and running it is
 * pointless. With this, the object is named in the viewer's packer field and the
 * reason is on the record, so the next reader does not repeat the investigation
 * above.
 *
 *
 * THE FINGERPRINT
 *
 * Every one of these is identical across the two hundred samples measured, and
 * each is a decision the packer's own template makes rather than a property of
 * the program inside it:
 *
 *     e_entry  == 0x0ba000f0     the stub's entry, from midgetpack's linker
 *                                script rather than from the payload
 *     e_phnum  == 6              its fixed segment layout
 *     the first 24 bytes of the stub, at the second PT_LOAD's file offset
 *
 * The stub bytes are the substantive half - a load address and a segment count
 * are two small numbers that a hand-linked ELF could reach by accident - and
 * they are checked at the offset the parse reports for that segment rather than
 * at a constant, so a sample built with a different template offset is rejected
 * rather than read at the wrong place.
 */

#include <kofmod/kofsig.h>
#include <kofmod/elf.h>

KOF_UNPACK_KIND(KOF_UNP_PACKER);

KOF_TARGET_FORMAT(KOF_FMT_ELF);

/* The stub is amd64, and unlike msf_xor_00.c this module never runs on a
 * formatless child - it produces none - so declaring it costs nothing. */
KOF_TARGET_ARCH(KOF_ARCH_X86_64);

/* The whole stub is 16618 bytes at the executable segment; the first 24 identify
 * it, and the file must be at least large enough to hold the layout above. */
KOF_TARGET_SIZE_MIN(32768);

#define MP_ENTRY   0x0ba000f0ull
#define MP_PHNUM   6u
#define MP_MARK_N  24u

/*
 * The opening of midgetpack's stub:
 *
 *     48 89 e5              mov  rbp, rsp
 *     53 51 52 56 57        push rbx, rcx, rdx, rsi, rdi
 *     48 89 ef              mov  rdi, rbp
 *     e8 03 0c 00 00        call +0xc03
 *     5f 5e 5a 59 5b        pop  rdi, rsi, rdx, rcx, rbx
 *     48 31 ed              xor  rbp, rbp
 *
 * A prologue, a call into the stub proper, the same registers back, and then the
 * ABI's "no frame pointer" - which is where a hand written entry point would
 * start, not where it would be twenty bytes in.
 */
static const uint8_t mp_mark[MP_MARK_N] = {
	0x48,0x89,0xe5,
	0x53,0x51,0x52,0x56,0x57,
	0x48,0x89,0xef,
	0xe8,0x03,0x0c,0x00,0x00,
	0x5f,0x5e,0x5a,0x59,0x5b,
	0x48,0x31,0xed
};

KOF_DEFINE_UNPACK
{
	const struct kof_elf_info *e = kof_elf(ctx);
	uint64_t at;
	uint32_t i, x_seen = 0;

	if (!e || !e->valid)
		return;
	if (e->entry_addr != MP_ENTRY || e->phnum != MP_PHNUM)
		return;

	/*
	 * The stub sits in the SECOND executable PT_LOAD-by-position, which is
	 * the first one that carries code: the layout puts a read-only header
	 * segment first. Found by walking the segments rather than by using the
	 * measured offset 0x10f0, because the offset is the same in all two
	 * hundred samples and that is a property of one build of the packer,
	 * while "the executable segment the entry point lands in" is a property
	 * of the format.
	 */
	at = KOF_NA;
	for (i = 0; i < e->seg_count && i < KOF_ELF_MAX_SEGMENTS; i++) {
		const struct kof_elf_seg *s = &e->seg[i];

		if (s->type != 1u || !(s->perm & KOF_PERM_X))
			continue;
		x_seen++;
		if (e->entry_addr >= s->mem_addr &&
		    e->entry_addr < s->mem_addr + s->mem_size) {
			at = s->file_off;
			break;
		}
	}
	if (at == KOF_NA || !kof_in_obj(at, MP_MARK_N))
		return;
	for (i = 0; i < MP_MARK_N; i++)
		if (kof_u8(at + i) != mp_mark[i])
			return;

	/*
	 * Named before the reason is recorded, so the viewer's packer field says
	 * "Midgetpack" rather than leaving the object labelled by whichever
	 * module spoke last. The value is the segment count, which is the one
	 * number here that would change if the packer's template did.
	 */
	kof_debug("Midgetpack.segments", x_seen);

	/*
	 * And that is the end of it: the reason, and no bytes.
	 *
	 * Emitting the payload segment as a child was considered and rejected.
	 * It is ciphertext with no key, so every module downstream would be run
	 * against noise and the object panel would carry an entry that can never
	 * say anything - the same trap ezuri.c describes for a wrong tail offset.
	 * A named packer and a recorded reason is the whole of what this file
	 * supports.
	 */
	KOF_UNP_BROKEN(KOF_UNP_ENCRYPTED);
}
