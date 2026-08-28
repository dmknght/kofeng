/*
 * ezuri.c - unpack an ELF crypted with Ezuri.
 *
 * Ezuri is a Go memory loader: the file on disk is a small Go stub whose whole
 * job is to decrypt a payload and run it with memfd_create, never touching the
 * filesystem. Everything a detection could match - every string, every symbol,
 * the family itself - is inside the payload. On disk the stub looks like any
 * other Go binary, which is why a packed sample matches nothing at all until it
 * is opened.
 *
 *
 * THE FORMAT, AND HOW THE BOUNDS ARE FOUND
 *
 * The packer writes four things and nothing else (ezuri.go, main):
 *
 *     stub bytes  ||  key  ||  iv  ||  AES-CFB(payload)
 *
 * so past everything the stub ELF claims there is:
 *
 *     [ 32 bytes ]  AES-256 key, printable ASCII
 *     [ 16 bytes ]  CFB IV, likewise
 *     [ rest     ]  AES-256-CFB ciphertext, to the end of the file
 *
 * The sizes are fixed at the source: randKey() makes 32 for the key and 16 for
 * the IV, both drawn from an alphabet of letters, digits and @#$% - and it is
 * always randKey(), because the prompt that would have taken a key from the user
 * reads into the IV variable twice and leaves the key empty.
 *
 * Nothing records the ciphertext length: it ends where the object does. So the
 * only bound to establish is where it starts, and that is the end of the last
 * thing the ELF accounts for - every section, every segment, the header block
 * and the section header table. Taking the maximum of those rather than reading
 * a field means an object that lies about one of them cannot move the payload
 * somewhere this would follow.
 *
 * There is no compression anywhere in it. A packed sample is full of zlib - nine
 * .zdebug_* sections of DWARF that Go compresses on its own - and none of it is
 * Ezuri's.
 *
 * ELF only, and that is the packer's limit rather than this module's: the stub
 * calls memfd_create and fork by their amd64 Linux syscall numbers.
 *
 * The published unpacker for this family finds the key by searching for the Go
 * symbol text ".main\0main.init" and stepping sixteen bytes past it. That works
 * on the samples it was written against and on none of the nine here: the
 * distance from that symbol to the key is a property of one Go release's symbol
 * table layout, not of Ezuri. Appended-past-the-end holds for all ten, the
 * published tool's own test file included.
 *
 *
 * WHY THE CIPHER IS IN HERE
 *
 * The host decompresses - DEFLATE, LZMA, NRV2 - and decrypts nothing, because
 * until now nothing needed it. Adding AES-CFB to the host for one packer would
 * put a cipher in the engine on the strength of a single caller; a module may
 * hold const tables and no state, which is exactly what a block cipher needs.
 * If a second family turns up wanting AES this belongs in the host instead, and
 * moving it is a smaller change than having guessed wrong in the other
 * direction.
 *
 * Only the forward cipher is built. CFB decryption encrypts the feedback block
 * and XORs; the inverse cipher and its tables are never reached.
 */

#include <kofmod/kofsig.h>
#include <kofmod/elf.h>

KOF_UNPACK_KIND(KOF_UNP_PACKER);

KOF_TARGET_FORMAT(KOF_FMT_ELF);

/*
 * The stub's own symbol, and the reason this module runs at all.
 *
 * Declared rather than searched for by hand so the host finds it in the pass it
 * is already making. It is the name of the loader's own function, so it is in
 * the Go symbol table of every build of the stub and in nothing else.
 */
KOF_DEFINE_STR(ezuri_mark, "main.runFromMemory", KOF_CASE_EXACT,
	       KOF_WORD_SUBSTRING);

#define AES_KEY_LEN   32u
#define AES_IV_LEN    16u
#define AES_BLK       16u
#define AES_ROUNDS    14u              /* AES-256 */
#define AES_RK_WORDS  ((AES_ROUNDS + 1u) * 4u)

/* Smallest payload worth trying: key, IV, and an ELF header to land on. */
#define EZURI_MIN_TAIL (AES_KEY_LEN + AES_IV_LEN + 64u)

/* How much is read and emitted at a time. Bounded so a large payload costs a
 * fixed amount of stack however big it is. */
#define CHUNK 1024u

static const uint8_t sbox[256] = {
	0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
	0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
	0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
	0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
	0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
	0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
	0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
	0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
	0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
	0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
	0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
	0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
	0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
	0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
	0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
	0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

static const uint8_t rcon[AES_ROUNDS] = {
	0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36,0x6c,0xd8,0xab,0x4d
};

static uint8_t xtime(uint8_t a)
{
	return (uint8_t)((a << 1) ^ ((a & 0x80u) ? 0x1bu : 0u));
}

static void aes256_expand(const uint8_t *key, uint8_t *rk)
{
	uint32_t i;

	for (i = 0; i < AES_KEY_LEN; i++)
		rk[i] = key[i];
	for (i = AES_KEY_LEN / 4u; i < AES_RK_WORDS; i++) {
		uint8_t t[4];
		uint32_t j, b = i * 4u;

		for (j = 0; j < 4u; j++)
			t[j] = rk[b - 4u + j];
		if (i % 8u == 0u) {
			uint8_t s = t[0];

			t[0] = (uint8_t)(sbox[t[1]] ^ rcon[i / 8u - 1u]);
			t[1] = sbox[t[2]];
			t[2] = sbox[t[3]];
			t[3] = sbox[s];
		} else if (i % 8u == 4u) {
			for (j = 0; j < 4u; j++)
				t[j] = sbox[t[j]];
		}
		for (j = 0; j < 4u; j++)
			rk[b + j] = (uint8_t)(rk[b - AES_KEY_LEN + j] ^ t[j]);
	}
}

/* One forward AES block, in place. */
static void aes256_encrypt(const uint8_t *rk, uint8_t *s)
{
	uint32_t r, i;

	for (i = 0; i < AES_BLK; i++)
		s[i] ^= rk[i];
	for (r = 1u; r <= AES_ROUNDS; r++) {
		uint8_t t[AES_BLK];

		for (i = 0; i < AES_BLK; i++)
			t[i] = sbox[s[i]];
		/* ShiftRows, written out: the state is column major, so row n
		 * moving left by n is a fixed permutation and a table of it
		 * would be a table to get wrong. */
		s[0]  = t[0];  s[1]  = t[5];  s[2]  = t[10]; s[3]  = t[15];
		s[4]  = t[4];  s[5]  = t[9];  s[6]  = t[14]; s[7]  = t[3];
		s[8]  = t[8];  s[9]  = t[13]; s[10] = t[2];  s[11] = t[7];
		s[12] = t[12]; s[13] = t[1];  s[14] = t[6];  s[15] = t[11];
		if (r != AES_ROUNDS) {
			for (i = 0; i < AES_BLK; i += 4u) {
				uint8_t a0 = s[i], a1 = s[i + 1u];
				uint8_t a2 = s[i + 2u], a3 = s[i + 3u];
				uint8_t x = (uint8_t)(a0 ^ a1 ^ a2 ^ a3);

				s[i]      = (uint8_t)(a0 ^ x ^ xtime(a0 ^ a1));
				s[i + 1u] = (uint8_t)(a1 ^ x ^ xtime(a1 ^ a2));
				s[i + 2u] = (uint8_t)(a2 ^ x ^ xtime(a2 ^ a3));
				s[i + 3u] = (uint8_t)(a3 ^ x ^ xtime(a3 ^ a0));
			}
		}
		for (i = 0; i < AES_BLK; i++)
			s[i] ^= rk[r * AES_BLK + i];
	}
}

/*
 * Where the appended payload starts: past everything this ELF accounts for.
 *
 * Segments are consulted as well as sections because a stripped build has no
 * section headers at all - one of the samples here is exactly that - and the
 * payload still sits past the last segment.
 */
static uint64_t ezuri_tail(const struct kof_elf_info *e)
{
	uint64_t end = 0;
	uint32_t i;

	if (e->hdr_claim_off + e->hdr_claim_len > end)
		end = e->hdr_claim_off + e->hdr_claim_len;
	if (e->shtab_claim_off + e->shtab_claim_len > end)
		end = e->shtab_claim_off + e->shtab_claim_len;
	for (i = 0; i < e->seg_count && i < KOF_ELF_MAX_SEGMENTS; i++) {
		uint64_t s = e->seg[i].file_off + e->seg[i].file_size;

		if (s > end)
			end = s;
	}
	for (i = 0; i < e->sec_count && i < KOF_ELF_MAX_SECTIONS; i++) {
		uint64_t s;

		/* SHT_NOBITS occupies memory and no file bytes; adding its size
		 * to its offset would put the tail past the end of the file. */
		if (e->sec[i].type == 8u)
			continue;
		s = e->sec[i].file_off + e->sec[i].file_size;
		if (s > end)
			end = s;
	}
	return end;
}

KOF_DEFINE_UNPACK
{
	const struct kof_elf_info *e = kof_elf(ctx);
	uint8_t rk[AES_RK_WORDS * 4u], fb[AES_BLK], ks[AES_BLK];
	uint8_t key[AES_KEY_LEN], buf[CHUNK];
	uint64_t at, end;
	uint32_t i;

	if (!e || !e->valid)
		return;
	if (kof_find_str_where(0, ctx->obj_size, ezuri_mark) == KOF_BROKEN)
		return;

	at = ezuri_tail(e);
	if (at >= ctx->obj_size ||
	    ctx->obj_size - at < EZURI_MIN_TAIL)
		return;

	/*
	 * Both are printable, or this is not the payload.
	 *
	 * The alphabet the packer draws them from is letters, digits and
	 * @ # $ % - spelled out rather than approximated by a range, because a
	 * range wide enough to hold @ (0x40) and z (0x7a) with one comparison
	 * excludes # $ % (0x23-0x25) at the other end, and real keys carry
	 * those. Forty-eight bytes of the alphabet in a row is a strong
	 * statement and costs one pass. Without it a wrong tail offset - an ELF
	 * with trailing bytes that are not Ezuri's - would be decrypted anyway
	 * and emitted as an object made of noise, which is worse than not
	 * unpacking: it is a child that every module then has to be run against.
	 */
	for (i = 0; i < AES_KEY_LEN + AES_IV_LEN; i++) {
		uint8_t c = kof_u8(at + i);

		if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
		      (c >= '0' && c <= '9') ||
		      c == '@' || c == '#' || c == '$' || c == '%'))
			return;
		if (i < AES_KEY_LEN)
			key[i] = c;
		else
			fb[i - AES_KEY_LEN] = c;
	}
	aes256_expand(key, rk);

	at += AES_KEY_LEN + AES_IV_LEN;
	end = ctx->obj_size;

	/*
	 * Name this module before it produces anything.
	 *
	 * The engine does not tell the callback which module made an object, so
	 * a recovered object is labelled with whatever the last module to speak
	 * called itself - and a module that says nothing gets its children
	 * labelled with someone else's name. This one came out as "via UPX.ELF"
	 * on a sample where UPX had run first, which reads as a claim about the
	 * format that nothing in the file supports.
	 */
	kof_debug("Ezuri.payload", end - at);

	/*
	 * CFB, block at a time, emitted in chunks.
	 *
	 * The feedback is the CIPHERTEXT block, so it is kept before the XOR
	 * overwrites the buffer. A trailing partial block is decrypted against
	 * as much key stream as it needs and ends the stream - there is nothing
	 * after it to feed.
	 */
	while (at < end) {
		uint32_t n = 0;

		while (n < CHUNK && at < end) {
			uint32_t k, have = (uint32_t)(end - at);
			uint8_t ct[AES_BLK];

			if (have > AES_BLK)
				have = AES_BLK;
			for (k = 0; k < have; k++)
				ct[k] = kof_u8(at + k);
			for (k = 0; k < AES_BLK; k++)
				ks[k] = fb[k];
			aes256_encrypt(rk, ks);
			for (k = 0; k < have; k++)
				buf[n + k] = (uint8_t)(ct[k] ^ ks[k]);
			for (k = 0; k < have; k++)
				fb[k] = ct[k];
			n += have;
			at += have;
		}
		if (!kof_emit(buf, n))
			return;         /* the host has stopped taking bytes */
	}
	kof_child();
}
