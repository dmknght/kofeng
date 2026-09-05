/*
 * sevenzip_parse.c - the 7z container, structure only.
 *
 * A fixed 32 byte header at the front that points at a variable header at the back,
 * with the coded streams in between. Three fields matter and all three are in the
 * front header: where the back header is, how large it is, and - once you look at
 * its first bytes - what was done to it.
 *
 *
 * WHY THIS STOPS WHERE IT DOES
 *
 * Because the file list is compressed. Measured over 44 real archives, 43 put their
 * header through a coder, so reading a single filename means running a decoder over
 * it first. This parse does not: identifying an object must not cost the
 * decompression of it, and a parser that decoded here would be one that decodes on
 * every file that happens to start with six bytes.
 *
 * What it does instead is answer the question that can be answered for nothing and
 * is worth more than the names: IS THIS READABLE AT ALL. 19 of those 44 encrypt the
 * header, and the coder id that says so sits in the clear at the front of the coded
 * header - four bytes, no decoding. An archive whose file list is ciphertext must
 * not come back clean, and that verdict is available here.
 *
 *
 * READING THE CODER ID WITHOUT DECODING ANYTHING
 *
 * The coded header opens with a PackInfo and an UnPackInfo describing how the
 * header itself was stored, and those are NOT coded - they cannot be, since they
 * are what tells a reader how to decode. So the walk below steps through them with
 * the format's variable length number encoding and stops at the first coder id.
 *
 * Every step is bounded against the object and against a step count, because this
 * is a structure read out of an untrusted file and the numbers in it decide how far
 * the cursor moves.
 */

#include "sevenzip_parse.h"
#include "../../kofdecomp/lzma.h"

#include <stdlib.h>
#include "../runlist.h"
#include "../../kofdecomp/lzma.h"

#include <string.h>

static const uint8_t SEVENZ_SIG[6] = { 0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c };

#define S_MAJOR      6u
#define S_MINOR      7u
#define S_NEXT_OFF   12u
#define S_NEXT_SIZE  20u

/* How far the small walk into the coded header may go. It only has to cross a
 * PackInfo and reach the first coder id; anything longer is a file describing
 * something other than its own header. */
#define HDR_PROBE_STEPS 64u

/*
 * The format's variable length number.
 *
 * The high bits of the first byte say how many bytes follow; what is left of that
 * byte is the top of the value. Returns zero and clears `ok` when the object ends
 * inside it, which is the only way this can fail.
 */
static uint64_t sz_num(kof_buf f, uint64_t *at, int *ok)
{
	uint8_t first = 0, b = 0;
	uint64_t v = 0;
	uint32_t i, mask = 0x80;

	*ok = 0;
	if (!kof_rd_u8(f, *at, &first))
		return 0;
	(*at)++;
	for (i = 0; i < 8; i++) {
		if (!(first & mask)) {
			v += (uint64_t)(first & (mask - 1u)) << (8u * i);
			*ok = 1;
			return v;
		}
		if (!kof_rd_u8(f, *at, &b))
			return 0;
		(*at)++;
		v |= (uint64_t)b << (8u * i);
		mask >>= 1;
	}
	*ok = 1;
	return v;
}

/*
 * Everything the coded header states about itself, in the clear.
 *
 * A 7z opens its coded header with a PackInfo and an UnPackInfo describing how that
 * header was stored, and those two cannot themselves be coded - they are what tells
 * a reader how to decode. So this walk reads: where the coded bytes are, how many
 * there are, what coder made them, its properties, and how long the result will be.
 *
 * That is exactly the set a decoder needs, which is why it is gathered here rather
 * than in the module: the walk is fiddly and format specific, and a module that had
 * to do it would be a second implementation of a variable length number decoder
 * inside a blob with no writable data.
 *
 * Every step is bounded against the object and against a step count, because this is
 * a structure read out of an untrusted file and the numbers in it decide how far the
 * cursor moves.
 */
static void hdr_probe(kof_buf f, uint64_t at, uint64_t end, struct kof_7z_info *z)
{
	uint64_t n_pack = 0, pack_pos = 0, pack_size = 0;
	uint32_t steps = 0, coder = 0;
	uint8_t id = 0, flags = 0;
	int ok;

	if (!kof_rd_u8(f, at, &id))
		return;
	at++;

	if (id == KOF_7Z_ID_PACKINFO) {
		pack_pos = sz_num(f, &at, &ok);
		if (!ok)
			return;
		n_pack = sz_num(f, &at, &ok);
		if (!ok || n_pack == 0 || n_pack > 4096u)
			return;
		for (;;) {
			if (++steps > HDR_PROBE_STEPS || at >= end)
				return;
			if (!kof_rd_u8(f, at, &id))
				return;
			at++;
			if (id == KOF_7Z_ID_END)
				break;
			if (id == KOF_7Z_ID_SIZE) {
				uint64_t k;

				for (k = 0; k < n_pack; k++) {
					uint64_t v = sz_num(f, &at, &ok);

					if (!ok)
						return;
					if (k == 0)
						pack_size = v;
				}
			}
		}
		if (!kof_rd_u8(f, at, &id))
			return;
		at++;
	}

	if (id != KOF_7Z_ID_UNPACK)
		return;
	if (!kof_rd_u8(f, at, &id) || id != KOF_7Z_ID_FOLDER)
		return;
	at++;

	sz_num(f, &at, &ok);                          /* numFolders */
	if (!ok)
		return;
	at++;                                         /* external */
	sz_num(f, &at, &ok);                          /* numCoders */
	if (!ok)
		return;
	if (!kof_rd_u8(f, at, &flags))
		return;
	at++;

	{
		uint32_t len = flags & 0x0fu, i;
		uint8_t c;

		if (len == 0 || len > 4u)
			return;
		for (i = 0; i < len; i++) {
			if (!kof_rd_u8(f, at + i, &c))
				return;
			coder = (coder << 8) | c;
		}
		at += len;
	}
	z->hdr_coder = coder;

	/*
	 * The coder's properties. For LZMA that is one packed byte holding lc, lp and
	 * pb, then a dictionary size this engine does not need - its decoder sizes its
	 * own window from the output buffer.
	 */
	if (flags & 0x20u) {
		uint64_t plen = sz_num(f, &at, &ok);
		uint8_t d;

		if (!ok)
			return;
		if (coder == KOF_7Z_CODER_LZMA && plen >= 1u &&
		    kof_rd_u8(f, at, &d)) {
			z->hdr_lc = (uint8_t)(d % 9u);
			z->hdr_lp = (uint8_t)((d / 9u) % 5u);
			z->hdr_pb = (uint8_t)(d / 45u);
			if (z->hdr_lc > KOF_LZMA_MAX_LC ||
			    z->hdr_lp > KOF_LZMA_MAX_LP ||
			    z->hdr_pb > KOF_LZMA_MAX_PB) {
				z->anomalies |= KOF_7Z_ANOM_UNKNOWN_CODER;
				return;
			}
		}
		at += plen;
	}

	/* kCodersUnPackSize: how long the decode will be. Bounded search, because
	 * anything between here and it is a property this does not need. */
	for (;;) {
		if (++steps > HDR_PROBE_STEPS || at >= end)
			return;
		if (!kof_rd_u8(f, at, &id))
			return;
		at++;
		if (id == KOF_7Z_ID_CODERS_SIZE)
			break;
		if (id == KOF_7Z_ID_END)
			return;
	}
	z->hdr_unpack_size = sz_num(f, &at, &ok);
	if (!ok) {
		z->hdr_unpack_size = 0;
		return;
	}

	/*
	 * Where the coded bytes are. packPos is stated from the end of the signature
	 * header, like everything else in this format, and both it and the size come
	 * out of the file - so the sum saturates and the caller checks it.
	 */
	z->hdr_pack_off = kof_sat_add(KOF_7Z_SIG_LEN, pack_pos);
	z->hdr_pack_size = pack_size;
}

/* ---- the decoded header, and the folders in it -------------------------------- */

/*
 * What the decode of the header is allowed to produce.
 *
 * A header is a file list, not content: over 369 real archives the largest decoded
 * to a few hundred kilobytes. Four megabytes is far above that and bounds an
 * archive whose declared header size is a lie - which costs an allocation, so it is
 * capped here rather than trusted.
 */
#define HDR_DECODE_MAX (4u << 20)

/* Steps the folder walk will take before deciding the header is not one. */
#define FOLDER_WALK_STEPS 65536u

/*
 * One coder's id and properties.
 *
 * The flags byte packs the id length into its low nibble, then says whether the
 * coder has extra stream counts and whether it carries properties. LZMA's
 * properties are the five bytes that decide lc, lp and pb - the same five this
 * file already reads off the front of a coded header, and the reason the content
 * needs no decoder that is not here.
 */
static int coder_read(kof_buf h, uint64_t *at, struct kof_7z_folder *fo,
		      uint32_t *n_in, uint32_t *n_out)
{
	uint8_t flags = 0, idb = 0;
	uint32_t idlen, i;
	int ok;

	if (!kof_rd_u8(h, *at, &flags))
		return 0;
	(*at)++;
	idlen = flags & 0x0fu;
	if (idlen == 0 || idlen > 8u)
		return 0;

	fo->coder = 0;
	for (i = 0; i < idlen; i++) {
		if (!kof_rd_u8(h, *at, &idb))
			return 0;
		(*at)++;
		fo->coder = (fo->coder << 8) | idb;
	}

	/*
	 * How many streams this coder joins.
	 *
	 * Simple coders are one in and one out and say nothing. A COMPLEX coder
	 * states both, and that is the only way BCJ2 announces that it needs four
	 * inputs - the counts used to be read and thrown away, which is exactly the
	 * information the walk then lacked.
	 */
	*n_in = 1;
	*n_out = 1;
	if (flags & 0x10u) {
		uint64_t vi, vo;

		vi = sz_num(h, at, &ok);
		if (!ok || vi == 0 || vi > 8u)
			return 0;
		vo = sz_num(h, at, &ok);
		if (!ok || vo == 0 || vo > 8u)
			return 0;
		*n_in = (uint32_t)vi;
		*n_out = (uint32_t)vo;
	}
	if (flags & 0x20u) {                    /* attributes */
		uint64_t n = sz_num(h, at, &ok);

		if (!ok || n > 64u)
			return 0;
		if (n >= 1u && fo->coder == KOF_7Z_CODER_LZMA) {
			uint8_t d = 0;

			if (!kof_rd_u8(h, *at, &d))
				return 0;
			if (d < 9u * 5u * 5u) {
				fo->pb = (uint8_t)(d / (9u * 5u));
				d = (uint8_t)(d % (9u * 5u));
				fo->lp = (uint8_t)(d / 9u);
				fo->lc = (uint8_t)(d % 9u);
			}
		}
		*at += n;
	}
	return 1;
}

/*
 * Walk the decoded header and record where each folder's bytes are.
 *
 * The shape is PackInfo then UnpackInfo: the first says where the packed streams
 * start and how long each is, the second says which coder turns them into what.
 * Neither is optional and both are counted, so this is a walk rather than a search
 * - the search form is what hdr_probe has to do, because it is reading a header it
 * cannot decode.
 *
 * A folder whose coder chain is longer than one link is recorded and not decoded:
 * a chain is a filter in front of a coder - BCJ before LZMA is the common one - and
 * running only the second half yields bytes that are not the file.
 */
/*
 * WHAT THE WALK LEARNS ABOUT EACH FOLDER, kept apart from kof_7z_folder.
 *
 * Apart because kof_7z_folder's layout is what modules compiled against this
 * ABI already read, and none of this belongs in it: these are working tables
 * the walk fills and consumes, and they land in the pack table after folder[]
 * where adding them moves nothing.
 *
 * One struct rather than seven locals so that reading a folder can be its own
 * function without that function taking seven tables as arguments.
 */
struct sz_walk {
	/* Packed streams per folder. */
	uint8_t  npk[KOF_7Z_MAX_FOLDERS];
	/*
	 * Which of a folder's packed streams feeds which BCJ2 input: 0 main,
	 * 1 call, 2 jump, 3 the range coder - and 0xff for every stream of
	 * every folder that is not BCJ2, which is nearly all of them.
	 */
	uint8_t  role[KOF_7Z_MAX_FOLDERS][8];
	/* Which coder each packed stream feeds, so its properties and its own
	 * output length can be attached to it once both are known. */
	uint8_t  pcod[KOF_7Z_MAX_FOLDERS][8];
	uint32_t cprop[KOF_7Z_MAX_FOLDERS][8];  /* lc | lp<<8 | pb<<16 */
	uint32_t cid[KOF_7Z_MAX_FOLDERS][8];
	uint64_t osize[KOF_7Z_MAX_FOLDERS][8];
	uint64_t psize[KOF_7Z_MAX_FOLDERS];
};

/*
 * ONE FOLDER: its coders, how they are wired, and which packed streams feed it.
 *
 * Lifted out of folders_walk, which was three hundred lines and eight levels
 * deep. The split is where it is because this is the one piece that REPEATS -
 * everything around it happens once for the archive - and because the loop body
 * was the whole of the depth: reading a folder is nested work, reading the
 * header around it is not.
 *
 * Returns 0 when the folder cannot be read, and that ends the WALK rather than
 * skipping one folder: the streams are read in order and their lengths are what
 * position the next one, so a folder that cannot be read leaves nothing after
 * it locatable either.
 */
static int one_folder(kof_buf h, uint64_t *at, struct kof_7z_info *z,
		      struct sz_walk *w, uint64_t i, uint64_t *n_out)
{
	int ok;

	struct kof_7z_folder *fo = &z->folder[i];
	uint64_t nc, k, tot_in = 0, tot_out = 0, n_bind, n_packed;
	uint64_t bind_in[8], bind_out[8], pk_idx[8];
	uint32_t cin[8], cout[8];

	fo->out_first = (uint32_t)*n_out;

	nc = sz_num(h, at, &ok);
	if (!ok || nc == 0 || nc > 8u)
		return 0;
	fo->n_coders = (uint8_t)nc;
	for (k = 0; k < nc; k++) {
		struct kof_7z_folder tmp;
		uint32_t ci = 0, co = 0;

		memset(&tmp, 0, sizeof tmp);
		if (!coder_read(h, at, &tmp, &ci, &co))
			return 0;
		cin[k] = ci;
		cout[k] = co;
		w->cid[i][k] = tmp.coder;
		w->cprop[i][k] = (uint32_t)tmp.lc | ((uint32_t)tmp.lp << 8) |
			      ((uint32_t)tmp.pb << 16);
		tot_in += ci;
		tot_out += co;
		if (k == 0) {
			fo->coder = tmp.coder;
			fo->lc = tmp.lc;
			fo->lp = tmp.lp;
			fo->pb = tmp.pb;
		} else {
			/*
			 * A later link is a transform over what came before.
			 * The LAST one wins because that is the one whose
			 * output is the folder's, and for BCJ2 it is the coder
			 * that has to be told apart from a plain filter.
			 */
			fo->filter = tmp.coder;
		}
	}

	/*
	 * Bind pairs, one per output stream past the first, and now READ
	 * rather than stepped over.
	 *
	 * A bind pair says an input is fed by another coder's output, which
	 * is precisely how the inputs that are NOT packed streams are named.
	 * What is left over is what the archive stores, and counting it is
	 * the whole reason a four input coder can be located at all.
	 */
	if (tot_out == 0 || tot_in < tot_out - 1u)
		return 0;
	n_bind = tot_out - 1u;
	if (n_bind > 8u)
		return 0;
	for (k = 0; k < n_bind; k++) {
		bind_in[k] = sz_num(h, at, &ok);
		if (!ok)
			return 0;
		bind_out[k] = sz_num(h, at, &ok);
		if (!ok)
			return 0;
	}

	n_packed = tot_in - n_bind;
	if (n_packed == 0 || n_packed > 8u)
		return 0;
	/*
	 * With one packed stream the format leaves the index out - it is the
	 * only input no bind pair claimed. With more, each is named, and the
	 * indices are stepped over: the streams arrive in this order anyway,
	 * and reordering them is the coder's business, not the walk's.
	 */
	if (n_packed > 1u) {
		for (k = 0; k < n_packed; k++) {
			pk_idx[k] = sz_num(h, at, &ok);
			if (!ok)
				return 0;
		}
	} else {
		/*
		 * With one packed stream the index is left out: it is the
		 * only input no bind pair claimed, and finding it is the
		 * same search the four stream case does.
		 */
		uint64_t q, b;

		pk_idx[0] = 0;
		for (q = 0; q < tot_in; q++) {
			for (b = 0; b < n_bind; b++)
				if (bind_in[b] == q)
					break;
			if (b == n_bind) {
				pk_idx[0] = q;
				break;
			}
		}
	}
	w->npk[i] = (uint8_t)n_packed;
	{
		uint64_t q, ib, c2;

		for (q = 0; q < n_packed; q++) {
			ib = 0;
			for (c2 = 0; c2 < nc; c2++) {
				if (pk_idx[q] < ib + cin[c2]) {
					w->pcod[i][q] = (uint8_t)c2;
					break;
				}
				ib += cin[c2];
			}
		}
	}

	/*
	 * BCJ2's four inputs, traced back to the packed streams that reach
	 * them.
	 *
	 * Three of them arrive through another coder - a bind pair says which
	 * output feeds them, and that output's coder has a packed input of its
	 * own. The fourth, the range coder's control bytes, is packed
	 * directly. Following that chain is the whole difference between
	 * knowing a folder is BCJ2 and being able to decode it, and guessing
	 * the usual order instead would give a file of the right length whose
	 * every branch is wrong.
	 */
	if (fo->filter == KOF_7Z_CODER_BCJ2 && nc >= 2u) {
		uint64_t in_base = 0, out_base = 0, c, j;

		/* Where the last coder's inputs start. */
		for (c = 0; c + 1u < nc; c++) {
			in_base += cin[c];
			out_base += cout[c];
		}
		if (cin[nc - 1u] == 4u) {
			for (j = 0; j < 4u; j++) {
				uint64_t want = in_base + j, b, src = want;
				int bound = 0;

				for (b = 0; b < n_bind; b++)
					if (bind_in[b] == want) {
						bound = 1;
						/* the coder whose output
						 * this is, then its own
						 * first input */
						{
							uint64_t o = bind_out[b];
							uint64_t ci2 = 0, ib = 0, ob = 0;

							for (ci2 = 0; ci2 < nc; ci2++) {
								if (o < ob + cout[ci2])
									break;
								ib += cin[ci2];
								ob += cout[ci2];
							}
							src = ib;
						}
						break;
					}
				(void)bound;
				for (k = 0; k < n_packed; k++)
					if (pk_idx[k] == src) {
						w->role[i][k] = (uint8_t)j;
						break;
					}
			}
		}
	}

	*n_out += tot_out;

	/*
	 * What this build can actually decode.
	 *
	 * One coder, or a coder and a filter, is the ordinary shape. BCJ2 is
	 * four inputs and is followed too, now that its packed streams can be
	 * located. Anything else is recorded and the folder is left with no
	 * decodable shape rather than the whole archive being abandoned - the
	 * offsets below are still assigned, so the folders that ARE readable
	 * stay readable.
	 */
	if (nc > 2u && fo->filter != KOF_7Z_CODER_BCJ2)
		z->anomalies |= KOF_7Z_ANOM_CODER_CHAIN;
	return 1;
}

static void folders_walk(kof_buf h, struct kof_7z_info *z, uint64_t base)
{
	uint64_t at = 0, pack_pos = 0, n_pack = 0, n_folders = 0, i, n_out = 0;
	struct sz_walk w;
	uint32_t steps = 0;
	uint8_t id = 0;
	int ok;

	if (!kof_rd_u8(h, at, &id) || id != KOF_7Z_ID_HEADER)
		return;
	at++;
	if (!kof_rd_u8(h, at, &id) || id != KOF_7Z_ID_STREAMS)
		return;
	at++;

	if (!kof_rd_u8(h, at, &id) || id != KOF_7Z_ID_PACKINFO)
		return;
	at++;
	pack_pos = sz_num(h, &at, &ok);
	if (!ok)
		return;
	n_pack = sz_num(h, &at, &ok);
	if (!ok || n_pack == 0)
		return;
	if (n_pack > KOF_7Z_MAX_FOLDERS) {
		z->anomalies |= KOF_7Z_ANOM_FOLDERS_FULL;
		n_pack = KOF_7Z_MAX_FOLDERS;
	}
	for (i = 0; i < KOF_7Z_MAX_FOLDERS; i++)
		w.psize[i] = 0;

	for (;;) {
		if (++steps > FOLDER_WALK_STEPS)
			return;
		if (!kof_rd_u8(h, at, &id))
			return;
		at++;
		if (id == KOF_7Z_ID_END)
			break;
		if (id == KOF_7Z_ID_SIZE) {
			for (i = 0; i < n_pack; i++) {
				uint64_t v = sz_num(h, &at, &ok);

				if (!ok)
					return;
				w.psize[i] = v;
			}
		} else if (id == KOF_7Z_ID_CRC) {
			/* Sizes are what this needs; a CRC block is skipped by
			 * walking to the end marker rather than by parsing it. */
			for (;;) {
				if (++steps > FOLDER_WALK_STEPS)
					return;
				if (!kof_rd_u8(h, at, &id))
					return;
				at++;
				if (id == KOF_7Z_ID_END)
					break;
			}
		}
	}

	if (!kof_rd_u8(h, at, &id) || id != KOF_7Z_ID_UNPACK)
		return;
	at++;
	if (!kof_rd_u8(h, at, &id) || id != KOF_7Z_ID_FOLDER)
		return;
	at++;
	n_folders = sz_num(h, &at, &ok);
	if (!ok || n_folders == 0)
		return;
	if (n_folders > KOF_7Z_MAX_FOLDERS) {
		z->anomalies |= KOF_7Z_ANOM_FOLDERS_FULL;
		n_folders = KOF_7Z_MAX_FOLDERS;
	}
	memset(&w, 0, sizeof w);
	memset(w.role, 0xff, sizeof w.role);
	memset(w.pcod, 0xff, sizeof w.pcod);
	at++;                                   /* external */

	for (i = 0; i < n_folders; i++)
		if (!one_folder(h, &at, z, &w, i, &n_out))
			return;


	if (!kof_rd_u8(h, at, &id) || id != KOF_7Z_ID_CODERS_SIZE)
		return;
	at++;
	/*
	 * One size per OUTPUT STREAM, not one per folder.
	 *
	 * A folder with a filter has two of them - what the coder produced and what
	 * the filter produced from it - and only the second is the folder's own
	 * output. Reading one per folder worked while every folder had a single
	 * coder and silently took the wrong number the moment one did not.
	 */
	{
		uint64_t seen = 0;

		for (i = 0; i < n_folders; i++) {
			struct kof_7z_folder *fo = &z->folder[i];
			uint64_t k;

			for (k = 0; k < fo->n_coders; k++) {
				uint64_t v = sz_num(h, &at, &ok);

				if (!ok)
					return;
				seen++;
				/* Every one of them, not only the last: a BCJ2
				 * folder's first three are what its three LZMA
				 * streams decode to, and each is needed to decode
				 * that stream on its own. */
				if (k < 8u)
					w.osize[i][k] = v;
				/* The last of a folder's streams is its output. */
				fo->unpack_size = v;
			}
		}
		(void)seen;
	}

	/*
	 * Where each folder's packed bytes are.
	 *
	 * packPos is stated from the end of the signature header, like every other
	 * offset in this format, and the folders take the packed streams in order -
	 * so folder n starts where the sum of the sizes before it ends.
	 */
	{
		/* kof_sat_add, not +: pack_pos and every w.psize[] below are
		 * unclamped sz_num() values off the stream, same as hdr_pack_off
		 * a few lines above (which does saturate, with the same
		 * reasoning) - a raw + here would let an attacker-chosen
		 * pack_pos or psize wrap cur/pk->off to a small value instead of
		 * pinning it past the file, undoing the point of computing a
		 * bound to check rather than trusting the declared one. */
		uint64_t cur = kof_sat_add(base, pack_pos), si = 0;

		for (i = 0; i < n_folders; i++) {
			uint32_t want = w.npk[i] ? w.npk[i] : 1u, j;

			if (si + want > n_pack)
				break;      /* the list ran out: stop where it did */

			/* The first is the folder's own, which is what every
			 * single-stream reader has always used. */
			z->folder[i].pack_off = cur;
			z->folder[i].pack_size = w.psize[si];

			for (j = 0; j < want; j++) {
				if (z->n_pack < KOF_7Z_MAX_PACK) {
					struct kof_7z_pack *pk =
						&z->pack[z->n_pack++];

					pk->off = cur;
					pk->size = w.psize[si];
					pk->folder = (uint32_t)i;
					pk->role = w.role[i][j];
					if (w.pcod[i][j] < 8u) {
						uint32_t cc = w.pcod[i][j];

						pk->coder = w.cid[i][cc];
						pk->out_size = w.osize[i][cc];
						pk->lc = (uint8_t)w.cprop[i][cc];
						pk->lp = (uint8_t)(w.cprop[i][cc] >> 8);
						pk->pb = (uint8_t)(w.cprop[i][cc] >> 16);
					}
				}
				cur = kof_sat_add(cur, w.psize[si]);
				si++;
			}
		}
		z->n_folders = (uint32_t)i;
	}
}

/* Decode the coded header, then read the folders out of it. */
static void content_probe(kof_buf f, struct kof_7z_info *z)
{
	uint8_t *out;
	uint64_t produced = 0;
	int st;

	if (z->header_kind != KOF_7Z_HDR_CODED ||
	    z->hdr_coder != KOF_7Z_CODER_LZMA || !z->hdr_pack_size)
		return;
	if (z->hdr_unpack_size == 0 || z->hdr_unpack_size > HDR_DECODE_MAX)
		return;
	if (!kof_in_range(f, z->hdr_pack_off, z->hdr_pack_size))
		return;

	out = malloc((size_t)z->hdr_unpack_size);
	if (!out)
		return;
	st = kof_lzma_decode(z->hdr_lc, z->hdr_lp, z->hdr_pb,
			     f.p + z->hdr_pack_off, z->hdr_pack_size,
			     out, z->hdr_unpack_size, &produced);
	if (produced)
		folders_walk(kof_buf_make(out, produced), z, KOF_7Z_SIG_LEN);
	else
		z->anomalies |= KOF_7Z_ANOM_HDR_UNREAD;
	(void)st;
	free(out);
}

/* ---- regions ------------------------------------------------------------------ */

static const uint32_t sz_cls_bit[KOF_7Z_CLS_COUNT] = {
	KOF_SCAN_7Z_HEADERS,
	KOF_SCAN_7Z_PACKED
};

/*
 * The archive's whole layout, as settled runs.
 *
 * One function so the per-class totals the parse records and the ranges the resolve
 * hands out can never describe the object differently.
 */
static void sz_runs(const struct kof_7z_info *z, uint64_t obj_size,
		    struct kof_runs *l, struct kof_run *buf, uint64_t *bytes)
{
	kof_runs_init(l, buf, 3u, KOF_7Z_CLS_COUNT);
	kof_runs_add(l, obj_size, 0, KOF_7Z_SIG_LEN, KOF_7Z_CLS_HEADERS);
	if (z->next_hdr_size && z->next_hdr_off > KOF_7Z_SIG_LEN)
		kof_runs_add(l, obj_size, KOF_7Z_SIG_LEN,
			     z->next_hdr_off - KOF_7Z_SIG_LEN, KOF_7Z_CLS_PACKED);
	if (z->next_hdr_size)
		kof_runs_add(l, obj_size, z->next_hdr_off, z->next_hdr_size,
			     KOF_7Z_CLS_HEADERS);
	kof_runs_settle(l, bytes);
}

static uint32_t sz_resolve_scan(const struct kof_obj_ctx *ctx, uint32_t mask,
				struct kof_range *out, uint32_t max_out)
{
	const struct kof_7z_info *z = (const struct kof_7z_info *)ctx->file_header;
	struct kof_run run[3];
	struct kof_runs l;
	uint64_t bytes[KOF_7Z_CLS_COUNT];

	if (!z || !z->valid || !out || max_out == 0)
		return 0;

	/*
	 * Three runs at most, so they are built here rather than kept in the view.
	 * The other containers store theirs because a walk discovered them one at a
	 * time and there is no second chance to work them out; here the whole layout
	 * is four numbers from the start header.
	 *
	 * They go through the same add-and-settle the parse uses, and that is not
	 * ceremony for three runs. The offsets are fields a file chose, so nothing
	 * stops a header claiming to live INSIDE the start header - and then the
	 * third run overlaps the first, in an order the resolve's complement walk
	 * reads as descending. Building them by hand skipped the settle, and a
	 * hostile-header fuzz round found it: overlapping regions mean a pattern
	 * matched twice in bytes that exist once.
	 */
	sz_runs(z, ctx->obj_size, &l, run, bytes);
	return kof_runs_resolve(l.v, l.n, mask, sz_cls_bit, KOF_SCAN_7Z_UNCLAIMED,
				ctx->obj_size, out, max_out);
}

/* ---- the parse ---------------------------------------------------------------- */

int kof_7z_sniff(kof_buf file)
{
	return file.n >= sizeof SEVENZ_SIG &&
	       memcmp(file.p, SEVENZ_SIG, sizeof SEVENZ_SIG) == 0;
}

int kof_7z_parse(kof_buf file, struct kof_7z_info *z, struct kof_obj_ctx *ctx)
{
	struct kof_runs l;
	struct kof_run run[3];
	uint64_t off = 0, size = 0;
	uint8_t first = 0;

	memset(z, 0, sizeof *z);
	z->version = KOF_7Z_INFO_VERSION;

	if (!kof_7z_sniff(file))
		return 0;
	z->valid = 1;
	z->header_kind = KOF_7Z_HDR_MISSING;

	if (!kof_rd_u8(file, S_MAJOR, &z->major) ||
	    !kof_rd_u8(file, S_MINOR, &z->minor) ||
	    !kof_rd_u64(file, S_NEXT_OFF, 0, &off) ||
	    !kof_rd_u64(file, S_NEXT_SIZE, 0, &size)) {
		z->anomalies |= KOF_7Z_ANOM_BAD_START;
		goto done;
	}
	if (z->major != 0)
		z->anomalies |= KOF_7Z_ANOM_BAD_VERSION;

	/*
	 * Both fields are stated relative to the END of the start header, and both
	 * come out of the file - so the sum is saturating and the result is checked
	 * against the object rather than believed.
	 */
	z->next_hdr_off = kof_sat_add(KOF_7Z_SIG_LEN, off);
	z->next_hdr_size = size;

	if (size == 0) {
		z->anomalies |= KOF_7Z_ANOM_HDR_EMPTY;
		goto done;
	}
	if (kof_clip_len(file.n, z->next_hdr_off, size) != size) {
		z->anomalies |= KOF_7Z_ANOM_HDR_PAST_EOF;
		goto done;
	}

	if (!kof_rd_u8(file, z->next_hdr_off, &first))
		goto done;

	if (first == KOF_7Z_ID_HEADER) {
		z->header_kind = KOF_7Z_HDR_PLAIN;
	} else if (first == KOF_7Z_ID_ENCODED) {
		hdr_probe(file, z->next_hdr_off + 1, z->next_hdr_off + size, z);
		if (z->hdr_pack_size &&
		    kof_clip_len(file.n, z->hdr_pack_off, z->hdr_pack_size) !=
		    z->hdr_pack_size) {
			/* The archive says its own header is somewhere the file does
			 * not reach. Cleared rather than clamped: a module handed a
			 * short range would decode whatever happens to be there. */
			z->hdr_pack_off = 0;
			z->hdr_pack_size = 0;
			z->anomalies |= KOF_7Z_ANOM_HDR_PAST_EOF;
		}
		if (z->hdr_coder == KOF_7Z_CODER_AES) {
			/*
			 * Not merely compressed: the file list is ciphertext. No
			 * build of this engine will read it, which is a different
			 * answer from "this build lacks a decoder" and is why the
			 * two are separate kinds.
			 */
			z->header_kind = KOF_7Z_HDR_ENCRYPTED;
			z->anomalies |= KOF_7Z_ANOM_ENCRYPTED;
		} else {
			z->header_kind = KOF_7Z_HDR_CODED;
			if (z->hdr_coder != KOF_7Z_CODER_LZMA &&
			    z->hdr_coder != KOF_7Z_CODER_LZMA2 &&
			    z->hdr_coder != KOF_7Z_CODER_COPY)
				z->anomalies |= KOF_7Z_ANOM_UNKNOWN_CODER;
		}
	} else {
		z->anomalies |= KOF_7Z_ANOM_UNKNOWN_CODER;
	}

done:
	/* The same three runs the resolve builds - the same call, so they cannot
	 * differ - settled once so the per-class totals are available to a module
	 * without resolving anything. */
	content_probe(file, z);
	sz_runs(z, file.n, &l, run, z->region_bytes);
	if (l.overlapped)
		z->anomalies |= KOF_7Z_ANOM_OVERLAP;

	ctx->format = KOF_FMT_7Z;
	ctx->obj_size = file.n;
	ctx->file_header = z;
	ctx->resolve_scan = sz_resolve_scan;
	return 1;
}

/* ---- names, for tools --------------------------------------------------------- */


#define X_BIT(b)  (b),
#define X_CASE(b) case (b): return #b;

const uint32_t kof_7z_region_bits[] = { SZ_REGIONS(X_BIT) };
_Static_assert(sizeof kof_7z_region_bits / sizeof kof_7z_region_bits[0] ==
	       KOF_7Z_REGION_COUNT, "region list and its count disagree");

const char *kof_7z_region_name(uint32_t bit)
{
	switch (bit) {
	SZ_REGIONS(X_CASE)
	default: return 0;
	}
}

#undef X_BIT
#undef X_CASE

const char *kof_7z_anomaly_name(unsigned index)
{
	static const char *const n[] = {
		"BAD_START", "HDR_PAST_EOF", "HDR_EMPTY", "ENCRYPTED",
		"UNKNOWN_CODER", "BAD_VERSION", "OVERLAP", "FOLDERS_FULL",
		"HDR_UNREAD", "CODER_CHAIN"
	};

	_Static_assert(sizeof n / sizeof n[0] == KOF_7Z_ANOM_COUNT,
		       "anomaly name table and its count disagree");
	return index < sizeof n / sizeof n[0] ? n[index] : 0;
}

const char *kof_7z_header_kind_name(uint32_t kind)
{
	switch (kind) {
	case KOF_7Z_HDR_PLAIN:     return "plain";
	case KOF_7Z_HDR_CODED:     return "compressed";
	case KOF_7Z_HDR_ENCRYPTED: return "ENCRYPTED";
	default:                   return "missing";
	}
}
