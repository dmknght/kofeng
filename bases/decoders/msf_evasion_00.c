/*
 * msf_evasion_00.c - the RC4 layer of metasploit's Windows evasion EXE.
 *
 * evasion/windows/windows_defender_exe (sinn3r, 2019) compiles a fixed C
 * template with Metasm, after putting the source through CRandomizer - which
 * inserts dead statements, fake functions and calls whose results are dropped -
 * so no two builds share a byte of code. What every build does share is the
 * four lines of template that are the module's whole point:
 *
 *     LPVOID lpBuf = VirtualAlloc(NULL, lpBufSize, MEM_COMMIT, 0x40);
 *     HANDLE proc  = OpenProcess(0x1F0FFF, false, 4);
 *     if (proc == NULL) {
 *       RC4("<key>", buf, (char*) lpBuf, <size>);
 *       ((void(*)())lpBuf)();
 *     }
 *
 * THE KEY IS IN THE FILE AS TEXT. Rex::Text.rand_text_alpha(32..64) makes it
 * and the template passes it as a C string literal, so it is a run of letters
 * in the read-only data with nothing in front of it. That is the whole of what
 * this module needs: the cipher is named in the source the file was compiled
 * from, and its key sits a section away from its ciphertext.
 *
 * NOTHING HERE READS AN OFFSET OUT OF THE CODE, and that is deliberate. The two
 * samples measured push the RC4 arguments in a different order - one fetches
 * the position-independent base between two pushes, the other before them -
 * which is what inserting statements does to register allocation. So the key
 * and the ciphertext are found by what they ARE: a run of letters of the right
 * length, and a span that decrypts under it to something shaped like a payload.
 *
 * WHAT THIS DOES NOT COVER. A build whose payload is not one of the Windows
 * ones msfvenom emits - anything not built on block_api - decrypts correctly
 * and is not recognised, because the test that finds the ciphertext is the
 * payload's own first instructions. The alternative is to accept any span that
 * decrypts to anything, which is every span.
 */

#include <kofmod/kofsig.h>
#include <kofshared/msf_pe.h>

KOF_ANALYZE_STEP(KOF_ANALYZE_DECRYPT);

/*
 * The wrapper is always a Windows EXE - the module hands what Metasm encoded
 * as :exe to file_create - so unlike the msfvenom encoders there is no
 * formatless layer underneath to also target.
 */
KOF_TARGET_FORMAT(KOF_FMT_PE);
KOF_TARGET_CONTENT("RC4");
KOF_TARGET_ARCH(KOF_ARCH_X86);

/* What comes out of it, so a heuristic that predicts Meterp routes here first.
 * Same declaration, same reason, as the msfvenom decoders beside this. */
KOF_TARGET_NAME(KOF_MALTYPE_TROJAN, "Meterp");

/* What rand_text_alpha(32..64) can produce and nothing wider: a longer run of
 * letters is a word from somewhere else in the file. */
#define KEY_MIN     32u
#define KEY_MAX     64u

/*
 * Below this the plaintext cannot be a payload - the smallest Windows stager
 * measured is a few hundred bytes. Above SCAN_MAX is not one of these files at
 * all: the wrapper is the template plus a payload, and the samples are 3 and
 * 4 KB. The bound is also what keeps the search below affordable, since it runs
 * once per candidate key over the whole object.
 */
#define PLAIN_MIN   64u
#define SCAN_MAX    (1u << 20)

#define CHUNK       1024u

/*
 * HOW A WINDOWS PAYLOAD BEGINS.
 *
 *     fc              cld
 *     e8 xx 00 00 00  call past the block_api helper
 *     60              pushad
 *     89 e5           mov ebp, esp
 *
 * block_api is the module-and-function lookup that every Windows payload
 * msfvenom emits is built on, and this is its first four instructions. The
 * displacement is the one byte that moves with the payload, so it is the one
 * byte not checked.
 */
#define HEAD_N      9u

static int looks_like_payload(const uint8_t *p)
{
	return p[0] == 0xfcu && p[1] == 0xe8u &&
	       p[3] == 0x00u && p[4] == 0x00u && p[5] == 0x00u &&
	       p[6] == 0x60u && p[7] == 0x89u && p[8] == 0xe5u;
}


/*
 * HOW MANY BYTES THE TEMPLATE SAID.
 *
 *     68 <size>     push the payload size
 *     ff 75 <disp>  push lpBuf
 *
 * The size and the buffer are the last two arguments of the RC4 call, so they
 * are pushed first and next to each other - the two samples agree on that even
 * though they disagree about the two pushes after it. `room` bounds what can be
 * believed: a size past the end of the object is some other push.
 *
 * Zero when nothing of this shape is in range, and then the caller decrypts to
 * the end of what it found. That is an honest fallback rather than a guess:
 * msfvenom appends 10 to 1024 bytes of its own junk to the payload before
 * encrypting, so the tail of the plaintext is noise either way.
 */
static uint32_t payload_size(const struct kof_obj_ctx *ctx, uint64_t room)
{
	uint64_t at;

	for (at = 0; kof_in_obj(at, 8); at++) {
		uint32_t n;

		if (kof_u8(at) != 0x68u || kof_u8(at + 5u) != 0xffu ||
		    kof_u8(at + 6u) != 0x75u)
			continue;
		n = kof_u32(at + 1u);
		if (n >= PLAIN_MIN && (uint64_t)n <= room)
			return n;
	}
	return 0;
}

/*
 * IS THIS ONE OF THESE FILES AT ALL - the cheap question, asked first.
 *
 *     6a 04           push 4          the System process
 *     6a 00           push 0          bInheritHandle = FALSE
 *     68 ff 0f 1f 00  push 0x1f0fff   PROCESS_ALL_ACCESS
 *
 * OpenProcess(PROCESS_ALL_ACCESS, FALSE, 4) is the template's anti-analysis
 * probe and the three pushes are one call's arguments, so CRandomizer - which
 * inserts whole statements - cannot get between them. Nine contiguous bytes,
 * measured present in these samples and no other PE.
 *
 * WHY A GATE AT ALL. The general unpacker pass runs every eligible module on
 * every object of its format, so without this the key search below - a cipher
 * schedule and a full sweep for each 32-to-64 letter run in the file - would
 * run on every x86 PE the scanner meets, and a Windows EXE's string tables are
 * full of runs that length. One linear scan for these nine bytes rules the file
 * out before any of that, the same way the msfvenom decoders test their
 * entry-point stub before decoding.
 */
static int has_template(const struct kof_obj_ctx *ctx, uint64_t n_obj)
{
	uint64_t at;

	for (at = 0; at + 9u <= n_obj; at++)
		if (kof_u8(at)      == 0x6au && kof_u8(at + 1u) == 0x04u &&
		    kof_u8(at + 2u) == 0x6au && kof_u8(at + 3u) == 0x00u &&
		    kof_u8(at + 4u) == 0x68u && kof_u8(at + 5u) == 0xffu &&
		    kof_u8(at + 6u) == 0x0fu && kof_u8(at + 7u) == 0x1fu &&
		    kof_u8(at + 8u) == 0x00u)
			return 1;
	return 0;
}

KOF_DEFINE_UNPACK
{
	uint8_t key[KEY_MAX], ks[HEAD_N], zero[HEAD_N];
	uint64_t n_obj = ctx->obj_size, at, ct = 0;
	uint32_t klen = 0, size, i;
	struct kof_capsid capsid;

	if (n_obj < PLAIN_MIN || n_obj > SCAN_MAX)
		return;

	/* The cheap gate, before the expensive search - see has_template. */
	if (!has_template(ctx, n_obj))
		return;

	/*
	 * EVERY RUN OF LETTERS OF THE RIGHT LENGTH IS TRIED, in the order they
	 * appear.
	 *
	 * CRandomizer's junk includes random strings of its own - it emits
	 * OutputDebugStringA of one - so the key is not the only candidate and
	 * cannot be picked by position or by being the longest. It is picked by
	 * being the one that decrypts something.
	 */
	for (at = 0; at < n_obj; at++) {
		uint8_t c = kof_u8(at);
		uint64_t end, p;

		if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')))
			continue;
		for (end = at; end < n_obj; end++) {
			uint8_t e = kof_u8(end);

			if (!((e >= 'A' && e <= 'Z') || (e >= 'a' && e <= 'z')))
				break;
		}
		if (end - at < KEY_MIN || end - at > KEY_MAX ||
		    end >= n_obj || kof_u8(end) != 0) {
			at = end;               /* past the run either way */
			continue;
		}

		klen = (uint32_t)(end - at);
		for (i = 0; i < klen; i++)
			key[i] = kof_u8(at + i);

		/*
		 * The keystream, once per key.
		 *
		 * RC4 starts at position zero whatever address the ciphertext
		 * happens to sit at, so the first nine bytes are the same for
		 * every span tried. Generated before the sweep rather than
		 * inside it, which is what turns "try this key at every offset"
		 * from a key schedule per offset into nine exclusive ors.
		 */
		/* The keystream's first bytes, once per candidate: RC4 over zeros is
		 * the keystream, and the host keys the cipher in one call instead of
		 * this module keying it per position - see kofmod/kofdecode.h. */
		capsid.algo = KOF_CAPSID_RC4;
		capsid.k32 = 0;
		capsid.key = key;
		capsid.key_len = klen;
		capsid.max_out = 0;
		for (p = 0; p < HEAD_N; p++)
			zero[p] = 0;
		if (kunp_capsid_apply(&capsid, zero, HEAD_N, ks, HEAD_N) != HEAD_N)
			continue;

		for (p = 0; p + HEAD_N <= n_obj; p++) {
			uint8_t head[HEAD_N];
			uint32_t k;

			for (k = 0; k < HEAD_N; k++)
				head[k] = (uint8_t)(kof_u8(p + k) ^ ks[k]);
			if (looks_like_payload(head)) {
				ct = p + 1u;    /* +1: zero means "not found" */
				break;
			}
		}
		if (ct)
			break;
		at = end;
	}
	if (!ct)
		return;
	ct--;

	/* Named before anything is produced, so the child is labelled by this
	 * module and not by whichever spoke last - see the same note in
	 * ezuri.c. */
	kof_debug("MSF.evasion.rc4.key", klen);

	size = payload_size(ctx, n_obj - ct);
	if (!size)
		size = (uint32_t)(n_obj - ct);

	/*
	 * A PE around it, because the payload is not a file and never was:
	 * the module handed these bytes to VirtualAlloc and called them. See
	 * msf_pe.h for what that reconstruction claims and what it does not.
	 * 32 bits, because this module declares ARCH_X86 and metasploit builds
	 * no 64-bit version of the evasion EXE.
	 */
	if (!msf_decl_pe(ctx, size, 32))
		return;

	/* From a fresh schedule: the nine bytes taken above were a test, and
	 * continuing from where that left off would decrypt the payload against
	 * the keystream starting nine bytes in. */
	/* The key and the range are this module's; RC4 is the host's. */
	capsid.algo = KOF_CAPSID_RC4;
	capsid.k32 = 0;
	capsid.key = key;
	capsid.key_len = klen;
	capsid.max_out = 0;
	if (!kunp_decrypt(&capsid, ct, size))
		return;                 /* the host has stopped taking bytes */

	kunp_rcstruct_supersedes();
	if (!kunp_rcstruct_done())
		kunp_rcstruct_broken(KOF_UNP_LIMIT);
}
