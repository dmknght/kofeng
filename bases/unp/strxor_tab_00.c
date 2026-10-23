/*
 * strxor_tab_00.c - the string table of the 111.exe family, read the way the program reads it.
 *
 * WHY IT WAS OFF, AND WHAT TURNS IT ON. It ran on every PE and anchored itself with a scan of the whole
 * file, one kof_u8 call per byte (sx_routine and the record loop both looked for 0xe8). Measured
 * on a 5.6 MB PE: 5.63 million accessor calls, 103 M of the 249 M instructions a scan of that file cost.
 * It was parked until it could anchor cheaply, and the three ways out named then were a bulk byte search
 * in the module ABI, a scan limited to executable sections, and a cheap precondition. It takes none of
 * them: a module already hands the host a pattern to look for (KOF_DEFINE_HEXSTR) and the host looks
 * with its own matcher - C, over the bytes, no accessor call - so the shape of a call site is DECLARED
 * (sx_site) and what this reads is the few places the host says it is. See sx_next_call.
 *
 * WHAT IT COSTS NOW, measured as callgrind Ir against the module absent: 0 to 2% on 11 clean PEs
 * (sx_table dismisses them), +18% on the family's own 5.6 MB file, where the work is real. The child of
 * that file is byte-identical to the one the original module produced, 518 records. What was narrowed to
 * get there: the gaps of sx_site are [0-12] and [0-40], taken from the 280 sites measured, where the
 * original read a 64-byte window; a key must be at least 8 hex digits followed by four zeros; the table
 * probe reads every 16 bytes, so a table needs a few more than 16 keys to be certain of 16 hits.
 * A call-site window holds the pushes of its neighbours, so sites closer than 64 bytes can read a length
 * a few bytes long: unchanged from the original, and not seen in the family's code.
 *
 * ---------------------------------------------------------------------------
 */
/*
 * A STRING TABLE READ THE WAY THE PROGRAM READS IT - FROM ITS OWN CALL SITES.
 *
 * WHAT IS HIDDEN. Every string this family uses is stored exclusive-ored with
 * a key kept immediately in front of it. One record, from the sample this was
 * written against - 111.exe, which is this family under VMProtect under
 * MPRESS, so none of it is visible until both of those have come off:
 *
 *     62 62 61 64 63 34 32 64 62 61 66 63 64 33 31 34   "bbadc42dbafcd314"
 *     00 00 00 00
 *     09 07 13 0a 06 58 01 56 4c 05 0a 0f               ^ the sixteen above
 *
 * and that payload is "kernel32.dll".
 *
 * ---- WHY THE SHAPE IS NOT THE ANCHOR, THOUGH IT LOOKS LIKE ONE -------------
 *
 * Written against the DATA first - sixteen hex digits, four zero bytes, a
 * payload that decodes to text - and it half worked, which is the worst
 * outcome available. The reason is in the disassembly, at the routine every
 * one of these calls: the decryption takes the LENGTH AS AN ARGUMENT.
 *
 *     push byte +0xc              ; 12 - "kernel32.dll"
 *     mov  edx, 0x41a060          ; the key
 *     mov  ecx, 0x41a074          ; the payload, key + 16 + 4
 *     call 0x12101
 *
 * and inside, with a few hundred junk calls between the instructions that
 * matter:
 *
 *     call strlen(key)     -> ecx
 *     xor  edx, edx
 *     mov  eax, i
 *     div  ecx             -> edx = i % strlen(key)
 *     mov  cl, [key + edx]
 *     mov  al, [data + i]
 *     xor  al, cl
 *     mov  [data + i], al
 *
 * So `data[i] ^= key[i % strlen(key)]` for i < len, and NEITHER len NOR the
 * key length is in the data. A reader of the bytes alone has to guess where a
 * payload stops, and the guesses all fail somewhere: stopping at the next run
 * of zeroes overruns the five records in nine that are not followed by four of
 * them, and stopping where the plaintext stops runs straight through the
 * separator, because a zero byte exclusive-ored with the key IS a key byte and
 * the key is ASCII hex. Measured against the 234 records the call sites give:
 * the data-shaped reader found 39, then 49 after two rounds of tuning.
 *
 * SO THE CALL SITES ARE THE ANCHOR. They are unambiguous - three arguments,
 * two of them pointers this module can check and one of them the exact length
 * - and they are what the program itself uses.
 *
 * ---- WHAT IS BEHIND IT -----------------------------------------------------
 *
 * kernel32.dll, LoadLibraryW, GetProcAddress, CreateToolhelp32Snapshot,
 * CryptUnprotectData, the NSS entry points, sqlite3_open16 and its friends -
 * and then the part that says what the program is for:
 *
 *     SELECT host_key, path, is_secure, expires_utc, name, encrypted_value
 *         FROM cookies
 *     SELECT name_on_card, card_number_encrypted, expiration_month,
 *         expiration_year FROM credit_cards
 *     "webextension@metamask.io":"
 *     SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall
 *     wallet.dat, logins.json, formhistory.sqlite, \ffcookies.txt, \CC.txt
 *     Content-Disposition: form-data; name="file"; filename="
 *
 * Every one of those is a string the engine could see the bytes of and not
 * read.
 *
 * ---- WHY A MODULE AND NOT A NORMALISER PASS --------------------------------
 *
 * It was tried in the generic executable normaliser, beside the base64 and hex
 * passes, and that is the wrong place twice over: it makes every PE and ELF in
 * a sweep pay a scan for a shape that belongs to one family, and a normaliser
 * says an object more plainly rather than recovering what was put out of
 * reach. So it anchors itself, and what it produces is the object with the
 * strings readable. The engine normalises THAT, which is the right order.
 */

#include <kofmod/kofsig.h>
#include <kofmod/pe.h>

KOF_ANALYZE_STEP(KOF_ANALYZE_DECRYPT);

KOF_TARGET_FORMAT(KOF_FMT_PE);
KOF_TARGET_CONTENT("StrXor-Table");

#define SX_BACK     64u    /* bytes before a call that may hold its arguments */
#define SX_NEED     16u    /* call sites the busiest routine must have */
#define SX_ALSO      2u    /* and what any OTHER one needs to be believed */
#define SX_CAND     64u    /* call targets tallied at once: the tally is
			    * first come, so a small table fills with
			    * one-off targets and the real second routine
			    * never gets a slot */
#define SX_MAX_REC 1024u   /* edits made to one object: two per record */
#define SX_MAX_LEN 4096u   /* one string; past this it is not one */
#define SX_MAX_KEY   64u   /* and its key */
#define SX_CHUNK   512u    /* bytes moved per emit */
#define SX_STRIDE   16u    /* bytes between reads of the table probe */
#define SX_KEY_MIN   8u    /* hex digits a key has at least */
#define SX_KEY_MAX  64u    /* and at most: SX_MAX_KEY, the routine's own bound */

/*
 * THE SHAPE OF A CALL SITE, DECLARED: `mov edx, imm32`, then `mov ecx, imm32`, then a call, with
 * whatever the obfuscator put between them. The immediates are left open - whether they are addresses
 * in THIS image is sx_addr's question, asked of the few places this finds - so what the host walks is
 * a superset of the sites, and every real one is in it: sx_ptrs reads a window of SX_BACK bytes back
 * from the call, so each gap here is the whole window.
 */
KOF_DEFINE_HEXSTR(sx_site, "BA ?? ?? ?? ?? [0-12] B9 ?? ?? ?? ?? [0-40] E8");

/*
 * WHETHER THE OBJECT HOLDS THE TABLE, asked first and cheaply.
 *
 * A record is its key - ASCII hex digits - then four zero bytes, and the family's table is a run of them.
 * Every key is at least SX_STRIDE characters, so a read every SX_STRIDE bytes of the data lands inside
 * every one: four hex digits in a word is a candidate, the run it sits in is walked out and must be
 * SX_KEY_MIN digits long and followed by the four zeros, and SX_NEED of those is a table. One is not:
 * a hex constant followed by padding is one (the family's image has 257 records; 11 clean PEs
 * measured here have none, one or two).
 *
 * Only what is not executable, and only what the file holds. This replaced a pattern the host searches
 * for (a run of hex digits and four zeros) because the host's search of a file that is mostly zeros
 * cost more than the scan it was meant to save - 25 M instructions on a 1.1 MB DLL - and a read a
 * sixteenth of the data costs about one instruction a byte of it.
 */
static int sx_hexc(uint32_t c)
{
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

static int sx_hex4(uint32_t w)
{
	return sx_hexc(w & 0xffu) && sx_hexc(w >> 8 & 0xffu) && sx_hexc(w >> 16 & 0xffu) &&
	       sx_hexc(w >> 24);
}

/* The run of hex digits around `at`, if it is a key: long enough and closed by four zeros.
 * Returns where the run ends, or 0. */
static uint64_t sx_key_end(const struct kof_obj_ctx *ctx, uint64_t at)
{
	uint64_t lo = at, hi = at;

	while (lo > 0 && at - lo < SX_KEY_MAX && sx_hexc(kof_u8(lo - 1u)))
		lo--;
	while (kof_in_obj(hi, 1u) && hi - lo < SX_KEY_MAX && sx_hexc(kof_u8(hi)))
		hi++;
	if (hi - lo < SX_KEY_MIN || !kof_in_obj(hi, 4u) || kof_u32(hi))
		return 0;
	return hi + 4u;
}

static int sx_table(const struct kof_obj_ctx *ctx, const struct kof_pe_info *pe)
{
	uint32_t i, found = 0;

	for (i = 0; i < pe->sec_count && i < KOF_PE_MAX_SECTIONS; i++) {
		const struct kof_pe_sec *s = &pe->sec[i];
		uint64_t at = s->file_off, end = s->file_off + s->file_size;

		if ((s->perm & KOF_PE_PERM_X) || !s->file_size || end < at)
			continue;
		for (; at + 4u <= end && kof_in_obj(at, 4u); at += SX_STRIDE) {
			uint64_t e;

			if (!sx_hex4(kof_u32(at)))
				continue;
			e = sx_key_end(ctx, at);
			if (!e)
				continue;
			if (++found >= SX_NEED)
				return 1;
			at = e;                 /* past the record's key: its payload is not another */
		}
	}
	return 0;
}

/*
 * WHERE THE CALLS ARE: the `call` of every place the host found sx_site, and none other, each once and in
 * order. A call is the last byte of the shape and lies within SX_BACK bytes of the `mov edx` that begins
 * it, so that window is what is read for each find; where two finds overlap, what the first read is not
 * read again. Nothing here looks at a byte that no find reaches.
 */
struct sx_it {
	uint64_t hit;   /* where the next find starts from */
	uint64_t at;    /* the next byte of the current window */
	uint64_t end;   /* and where it ends */
};

static uint64_t sx_next_call(const struct kof_obj_ctx *ctx, struct sx_it *it)
{
	for (;;) {
		uint64_t h;

		while (it->at < it->end) {
			uint64_t e = it->at++;

			if (e + 5u < ctx->obj_size && kof_u8(e) == 0xe8u)
				return e;
		}
		if (it->hit >= ctx->obj_size)
			return ctx->obj_size;
		h = kof_find_str_where(it->hit, ctx->obj_size - it->hit, sx_site);
		if (h == KOF_BROKEN)
			return ctx->obj_size;
		it->hit = h + 1u;
		if (h + 10u > it->at)
			it->at = h + 10u;
		it->end = h + SX_BACK + 1u;
	}
}

/*
 * ONE EDIT. `klen` zero means BLANK IT - see the note where the keys are
 * added - and anything else means decode `len` bytes against the key at `key`.
 */
struct sx_rec {
	uint32_t off;      /* where it is, in the file */
	uint32_t key;      /* the key, when there is one */
	uint16_t len;
	uint16_t klen;
};

/* A section's file offset for an RVA, or 0 when nothing holds it. Zero is not
 * a valid answer either way: no section starts at offset zero. */
static uint64_t sx_off_of(const struct kof_pe_info *pe, uint64_t rva)
{
	uint32_t i;

	for (i = 0; i < pe->sec_count && i < KOF_PE_MAX_SECTIONS; i++) {
		const struct kof_pe_sec *s = &pe->sec[i];
		uint64_t span = s->mem_size > s->file_size ? s->mem_size
							  : s->file_size;

		if (!s->file_size || rva < s->mem_rva ||
		    rva - s->mem_rva >= span)
			continue;
		return s->file_off + (rva - s->mem_rva);
	}
	return 0;
}

/*
 * TAB, CARRIAGE RETURN AND NEWLINE COUNT AS TEXT.
 *
 * Left out at first, and twelve of the sample's records begin with one - the
 * report this thing builds is laid out with them, "\t- Login Data", "\t%s",
 * "\r\n". A record whose FIRST byte is a tab failed at once, so its bound came
 * out zero and it was never read at all.
 */
static int sx_text(uint8_t c)
{
	return (c >= 0x20u && c < 0x7fu) ||
	       c == 0x09u || c == 0x0au || c == 0x0du;
}

/*
 * The two pointer arguments in front of a call, read backwards from it.
 *
 * `mov ecx` is the nearest and `mov edx` comes before it - that order is the
 * one this compiler produced at every site measured, and checking it is what
 * stops the walk drifting into the previous call's arguments.
 *
 * THE LENGTH IS NOT READ HERE, and that is the whole lesson of this file. It
 * is a push, and the pushes are not in one place: most sites put it in front
 * of both movs and a good few put it BETWEEN them, while the obfuscator
 * sprinkles `push 0` among them all. Picking one by position got it wrong
 * either way round - the cookies query took the length belonging to the record
 * before it and came out cut at "...name, encrypt". So the caller chooses it
 * with something position cannot give: see sx_len.
 */
/*
 * AND THE IMMEDIATE HAS TO BE AN ADDRESS IN THIS IMAGE.
 *
 * A backwards byte scan does not know where an instruction begins, and
 * `mov ecx, 0x41b948` is B9 48 B9 41 00 - it CONTAINS a second B9. Scanning
 * back from the call meets that one first, reads the four bytes after it and
 * comes away with 0x69e00041, which is nothing. Every such site was thrown
 * away: twenty-two records, among them the Firefox cookie and form-history
 * queries and the multipart headers the stolen files are posted with.
 *
 * The operand settles it. A real one points into the image and a byte taken
 * from the middle of one does not, so the scan keeps walking back until it
 * finds an operand that could be an address - and that is the instruction's
 * true start.
 */
static int sx_addr(const struct kof_pe_info *pe, const struct kof_obj_ctx *ctx,
		   uint64_t v)
{
	return v >= pe->image_base && v - pe->image_base < ctx->obj_size;
}

static int sx_ptrs(const struct kof_obj_ctx *ctx, const struct kof_pe_info *pe,
		   uint64_t call_at, uint64_t *key_rva, uint64_t *dat_rva,
		   uint64_t *win_lo)
{
	uint64_t lo = call_at > SX_BACK ? call_at - SX_BACK : 0;
	uint64_t i, p_ecx = 0, p_edx = 0;

	for (i = call_at; i-- > lo; )
		if (kof_u8(i) == 0xb9u && kof_in_obj(i, 5u) &&
		    sx_addr(pe, ctx, kof_u32(i + 1u))) {
			p_ecx = i;
			break;
		}
	if (!p_ecx)
		return 0;
	for (i = p_ecx; i-- > lo; )
		if (kof_u8(i) == 0xbau && kof_in_obj(i, 5u) &&
		    sx_addr(pe, ctx, kof_u32(i + 1u))) {
			p_edx = i;
			break;
		}
	if (!p_edx)
		return 0;
	*dat_rva = kof_u32(p_ecx + 1u);
	*key_rva = kof_u32(p_edx + 1u);
	*win_lo = lo;
	return 1;
}

/*
 * THE LENGTH: THE LARGEST PUSH IN THE WINDOW THAT THE PAYLOAD CAN BEAR.
 *
 * `cap` is how far the payload decodes to printable text - the point past
 * which the answer is certainly wrong - and every push immediate in the window
 * is a candidate. The real length is among them and cannot exceed `cap`, so
 * the largest candidate that fits is it.
 *
 * WHY THE LARGEST AND NOT THE NEAREST. A too-small candidate also decodes
 * cleanly, because it is a prefix of the right answer - which is exactly how
 * the cookies query lost its last twenty bytes while looking perfectly
 * plausible. Nothing about position distinguishes the two; length does.
 *
 * Measured across the sample's 250 call sites: choosing by position read 198,
 * choosing this way reads 215.
 */
static uint32_t sx_len(const struct kof_obj_ctx *ctx, uint64_t lo,
		       uint64_t call_at, uint64_t dat, uint32_t cap)
{
	uint64_t i;
	uint32_t best = 0;

	for (i = lo; i + 1u < call_at; i++) {
		uint32_t v = 0;

		if (kof_u8(i) == 0x6au)
			v = kof_u8(i + 1u);
		else if (kof_u8(i) == 0x68u && i + 5u <= call_at)
			v = kof_u32(i + 1u);   /* bounded by the call, or the
						* call's own rel32 reads as a
						* length */
		if (v < 1u || v > cap || v <= best)
			continue;
		/* Only one that lands on a separator - see the caller. */
		if (kof_in_obj(dat + v, 1u) && !kof_u8(dat + v))
			best = v;
	}
	return best;
}

/* Where a call goes, or the object's size when it goes nowhere in it. */
static uint64_t sx_target(const struct kof_obj_ctx *ctx, uint64_t at)
{
	int64_t rel;

	if (!kof_in_obj(at, 5u) || kof_u8(at) != 0xe8u)
		return ctx->obj_size;
	rel = (int64_t)(int32_t)kof_u32(at + 1u);
	if (rel < 0 && (uint64_t)(-rel) > at + 5u)
		return ctx->obj_size;
	return at + 5u + (uint64_t)rel;
}

/*
 * WHICH ROUTINE IT IS, FOUND BY COUNTING RATHER THAN BY RECOGNISING.
 *
 * The decryption itself is buried in a few hundred junk calls and no byte
 * pattern of it is worth writing down. What IS unmistakable is its shape from
 * the outside: one address called from many places, each call preceded by two
 * immediate pointers and a length. So every call whose arguments have that
 * shape votes for its target, and the address with the most votes is it.
 */
static uint32_t sx_routine(const struct kof_obj_ctx *ctx,
			   const struct kof_pe_info *pe, uint64_t *out,
			   uint32_t cap_out)
{
	uint64_t cand[SX_CAND];
	uint32_t hits[SX_CAND], n = 0, i, best = 0, kept = 0;
	uint64_t at;
	struct sx_it it = { 0, 0, 0 };

	while ((at = sx_next_call(ctx, &it)) < ctx->obj_size) {
		uint64_t key, dat, tgt, wlo;

		tgt = sx_target(ctx, at);
		if (tgt >= ctx->obj_size)
			continue;
		if (!sx_ptrs(ctx, pe, at, &key, &dat, &wlo))
			continue;
		for (i = 0; i < n; i++)
			if (cand[i] == tgt) {
				hits[i]++;
				break;
			}
		if (i == n && n < SX_CAND) {
			cand[n] = tgt;
			hits[n] = 1;
			n++;
		}
	}
	if (!n)
		return 0;
	for (i = 0; i < n; i++)
		if (hits[i] > hits[best])
			best = i;
	if (hits[best] < SX_NEED)
		return 0;
	/*
	 * AND EVERY OTHER ROUTINE OF THE SAME SHAPE, NOT ONLY THE BUSIEST.
	 *
	 * Taking one address was enough to read the string table and missed
	 * the thing that matters most. This family has a SECOND decryptor -
	 * five call sites against the first one's 244, the same repeating-key
	 * exclusive-or but with the key hard coded rather than passed - and
	 * behind it is the address the program reports to:
	 * `http://185.181.10.208/`. A count is a measure of how much a routine
	 * is used, not of whether it is one.
	 *
	 * So the busiest still has to clear SX_NEED - that is what says this
	 * file has such a thing at all - and once it has, any other address
	 * called the same way with as few as SX_ALSO sites is read too. Each
	 * record still has to decode to text on its own, so a wrong guess
	 * here costs nothing.
	 */
	for (i = 0; i < n && kept < cap_out; i++)
		if (hits[i] >= SX_ALSO)
			out[kept++] = cand[i];
	return kept;
}

void kof_unpack(const struct kof_obj_ctx *ctx)
{
	const struct kof_pe_info *pe = kof_pe(ctx);
	struct sx_rec rec[SX_MAX_REC];
	uint64_t routine[SX_CAND], at;
	struct sx_it it;
	uint32_t n = 0, i, j, n_rout;

	if (!pe->valid || !pe->sec_count || !sx_table(ctx, pe))
		return;
	n_rout = sx_routine(ctx, pe, routine, SX_CAND);
	if (!n_rout)
		return;

	/* Every call to it, with the arguments it was given. */
	it.hit = it.at = it.end = 0;
	while (n < SX_MAX_REC && (at = sx_next_call(ctx, &it)) < ctx->obj_size) {
		uint64_t key_rva, dat_rva, key_off, dat_off, wlo;
		uint32_t len, klen, cap, zcap;

		{
			uint64_t t = sx_target(ctx, at);

			for (j = 0; j < n_rout; j++)
				if (routine[j] == t)
					break;
			if (j == n_rout)
				continue;
		}
		if (!sx_ptrs(ctx, pe, at, &key_rva, &dat_rva, &wlo))
			continue;
		if (key_rva < pe->image_base || dat_rva < pe->image_base)
			continue;
		key_off = sx_off_of(pe, key_rva - pe->image_base);
		dat_off = sx_off_of(pe, dat_rva - pe->image_base);
		if (!key_off || !dat_off || !kof_in_obj(key_off, 2u))
			continue;
		/* The key is NUL terminated and the routine measures it with
		 * strlen, so that is what decides the modulus. */
		for (klen = 0; klen < SX_MAX_KEY; klen++) {
			if (!kof_in_obj(key_off + klen, 1u))
				break;
			if (!kof_u8(key_off + klen))
				break;
		}
		if (!klen || klen >= SX_MAX_KEY)
			continue;
		/*
		 * HOW FAR THE RECORD CAN POSSIBLY REACH.
		 *
		 * Two stops, and the raw zero is the one that matters. A
		 * record is followed by at least one zero byte, and a zero
		 * exclusive-ored with the key IS a key byte - the key is ASCII
		 * hex, so the separator DECODES TO TEXT and a text-only bound
		 * runs straight through it into the next record. Under that,
		 * a nine byte record read as thirteen and came out
		 * "LocalFree5d0a", the tail being its own key; worse, the
		 * over-long range then swallowed the record after it, which
		 * was left for a second pass to find - and that second pass is
		 * a second child of the same file.
		 *
		 * A zero byte inside ciphertext is possible - it means the
		 * plaintext byte equalled its key byte - and costs a record
		 * its tail when it happens. That is the cheaper mistake by
		 * far: it is local, and the alternative walks into the
		 * neighbours.
		 */
		for (cap = 0; cap < SX_MAX_LEN; cap++) {
			if (!kof_in_obj(dat_off + cap, 1u))
				break;
			if (!sx_text((uint8_t)(kof_u8(dat_off + cap) ^
					       kof_u8(key_off + (cap % klen)))))
				break;
		}
		/* And where the ciphertext first stops, which is a second
		 * bound and usually the tighter one. */
		for (zcap = 0; zcap < cap; zcap++)
			if (!kof_in_obj(dat_off + zcap, 1u) ||
			    !kof_u8(dat_off + zcap))
				break;
		if (!cap)
			continue;
		/*
		 * THE LENGTH THAT ENDS ON THE SEPARATOR, AND NOTHING LONGER.
		 *
		 * A record is followed by at least one zero byte, so the
		 * answer has a zero AFTER it. That is asked of the call's own
		 * push values first - they are the real lengths - and it is
		 * what keeps a pick from running past the record into the one
		 * behind it, which is how an over-long range swallowed its
		 * neighbour and left it for a second pass to find.
		 *
		 * Failing that, the first zero in the ciphertext. It is only a
		 * fallback because ciphertext CAN hold a zero - it means the
		 * plaintext byte equalled its key byte - and on this sample
		 * that costs the credit-card query its last seventy
		 * characters if it is used as the primary bound.
		 */
		len = sx_len(ctx, wlo, at, dat_off, cap);
		if (!len)
			len = zcap;
		rec[n].off = (uint32_t)dat_off;
		rec[n].key = (uint32_t)key_off;
		rec[n].len = (uint16_t)len;
		rec[n].klen = (uint16_t)klen;
		n++;
		/*
		 * AND THE KEY GOES, once what it hid has been read.
		 *
		 * It is dead material after that: sixteen random hex
		 * characters per string, two hundred of them, sitting between
		 * every pair of recovered strings. They are not evidence -
		 * they are a different sixteen in every build - and they are
		 * not free either: they land in the string and block pass of
		 * whatever reads this object, so a table of two hundred real
		 * strings arrives interleaved with two hundred pieces of
		 * noise.
		 *
		 * BLANKED, NOT REMOVED. Writing zeroes keeps every offset in
		 * the object exactly where it was - the headers, the sections
		 * and anything that points into this table still mean what
		 * they meant - and a zero run is what the normaliser collapses
		 * next, so it costs nothing downstream either.
		 */
		if (n < SX_MAX_REC) {
			rec[n].off = (uint32_t)key_off;
			rec[n].key = 0;
			rec[n].len = (uint16_t)klen;
			rec[n].klen = 0;
			n++;
		}
	}
	if (!n)
		return;

	/*
	 * A KEY IS NOT BLANKED WHERE A PAYLOAD LIVES.
	 *
	 * The two edit kinds can name overlapping bytes - a key read from one
	 * call site can sit inside the range another site calls its payload -
	 * and the emit below keeps whichever comes first and drops the other.
	 * When the dropped one is a PAYLOAD, that record is left enciphered,
	 * the child still holds it, and the module finds it on the next pass:
	 * one more child of the same file, measured, with twelve records in
	 * it.
	 *
	 * Blanking is cosmetic and decoding is not, so the key gives way.
	 * Dropped here rather than at the emit, because by then the order has
	 * already decided it.
	 */
	for (i = 0; i < n; i++) {
		if (rec[i].klen)
			continue;               /* a payload, not a key */
		for (j = 0; j < n; j++) {
			if (!rec[j].klen)
				continue;
			if (rec[i].off + rec[i].len <= rec[j].off ||
			    rec[j].off + rec[j].len <= rec[i].off)
				continue;
			rec[i].len = 0;         /* struck out */
			break;
		}
	}

	/*
	 * THE PARENT, WITH THESE RANGES CHANGED.
	 *
	 * Not an order, not a sort, not an overlap to resolve - the engine
	 * holds the bytes and each record is written where it belongs. What
	 * this replaces got both of those wrong: once advancing past a record
	 * without copying it, which cost the child 114353 bytes, and once
	 * letting an over-long record swallow the one behind it so a second
	 * pass found it and mis-read it.
	 *
	 * It is also what stops this module meeting its own output. A derived
	 * object is never offered back to the module that derived it, so the
	 * hand-written guard that used to be here - and the wrong one before
	 * it - are gone.
	 */
	if (!kunp_rcstruct_derive())
		kunp_rcstruct_broken(KOF_UNP_LIMIT);
	for (i = 0; i < n; i++) {
		uint8_t b[SX_CHUNK];
		uint32_t at = 0;

		if (!rec[i].len)
			continue;               /* struck out */
		while (at < rec[i].len) {
			uint32_t left = (uint32_t)rec[i].len - at, k;
			unsigned c = left > SX_CHUNK ? SX_CHUNK
						     : (unsigned)left;

			for (k = 0; k < c; k++)
				b[k] = rec[i].klen
				     ? (uint8_t)(kof_u8((uint64_t)rec[i].off +
							at + k) ^
						 kof_u8((uint64_t)rec[i].key +
							((at + k) % rec[i].klen)))
				     : 0u;
			if (!kunp_rcstruct_poke((uint64_t)rec[i].off + at, b, c))
				kunp_rcstruct_broken(KOF_UNP_LIMIT);
			at += c;
		}
	}

	kof_debug("StrXor.tab.records", n);

	/*
	 * THE SAME OBJECT, SAID SO. Every byte outside a payload is copied
	 * through, so the child is the parent with its strings readable - its
	 * headers, its sections and every offset in them still mean what they
	 * meant, and the engine reads it as the PE it is.
	 */
	if (!kunp_rcstruct_done())
		kunp_rcstruct_broken(KOF_UNP_LIMIT);
}
