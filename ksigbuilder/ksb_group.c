/*
 * ksb_group.c - PACK: which pack an artefact goes in, and what the pack is
 *    called.
 */

#include "ksb.h"

static int bucket_of_format(uint32_t fmt)
{
	switch (fmt) {
	case KOF_FMT_ELF:     return BUCKET_ELF;
	case KOF_FMT_PE:      return BUCKET_PE;
	case KOF_FMT_MACHO:   return BUCKET_MACHO;
	case KOF_FMT_GZIP:
	case KOF_FMT_ZIP:
	case KOF_FMT_TAR:
	case KOF_FMT_7Z:
	case KOF_FMT_RAR:
	case KOF_FMT_XZ:
	case KOF_FMT_CAB:
	case KOF_FMT_LHA:
	case KOF_FMT_ARJ:
	case KOF_FMT_BZIP2:
	/*
	 * DOCZIP IS AN ARCHIVE HERE, not a document, and the distinction is
	 * about what an unpacker targets rather than what a user opens.
	 *
	 * A .docx IS a zip file; the unpacker that opens one is the zip
	 * unpacker, and it declares ZIP|DOCZIP. Filing DOCZIP under documents
	 * split that mask across two buckets, which made it bucketless and gave
	 * it a pack of its own sitting next to unpack-archive - the exact
	 * untidiness this grouping exists to remove. The doc bucket is for
	 * containers that are documents in their own right: OLE, RTF, PDF.
	 */
	case KOF_FMT_DOCZIP:  return BUCKET_ARCHIVE;
	case KOF_FMT_DOCOLE:
	case KOF_FMT_RTF:
	case KOF_FMT_CHM:
	case KOF_FMT_PDF:     return BUCKET_DOC;
	/*
	 * ONE BUCKET FOR BOTH, AND IT IS NAMED AFTER THE ONE THAT HAS RULES.
	 *
	 * KOF_FMT_TEXT is a file nothing claimed that reads as text;
	 * KOF_FMT_SCRIPT is a file that named its own interpreter. They share a
	 * pack because a rule for one is prefiltered against the other for
	 * free, and the pack is called "script" because that is what every
	 * module in it targets - a reader looking for the webshells was being
	 * pointed at a file called "text".
	 */
	case KOF_FMT_SCRIPT:
	case KOF_FMT_TEXT:    return BUCKET_SCRIPT;
	case KOF_FMT_UNKNOWN: return BUCKET_RAW;
	case KOF_EVT_PROC:    return BUCKET_PROC;
	case KOF_EVT_AMSI:    return BUCKET_AMSI;
	default:              return BUCKET_NONE;
	}
}

const char *ksb_bucket_name(int b)
{
	switch (b) {
	case BUCKET_ELF:     return "elf";
	case BUCKET_PE:      return "pe";
	case BUCKET_MACHO:   return "macho";
	case BUCKET_ARCHIVE: return "archive";
	case BUCKET_DOC:     return "doc";
	case BUCKET_SCRIPT:  return "script";
	case BUCKET_RAW:     return "raw";
	case BUCKET_PROC:    return "proc";
	case BUCKET_AMSI:    return "amsi";
	default:             return "";
	}
}

/*
 * The bucket a whole target mask belongs to, or BUCKET_NONE when its bits do
 * not agree.
 *
 * A module targeting ELF and PE together is not an executable-bucket module,
 * it is its own thing - and it keeps its own pack rather than being filed under
 * whichever half was tested first.
 */
/*
 * The bucket a whole target LIST belongs to.
 *
 * A list now rather than a mask, so the loop is over the ids a module actually
 * named instead of over every bit position - see n_target in dbloader.h. A module
 * that named everything belongs in no bucket, which is what BUCKET_NONE says.
 */
int ksb_bucket_of_targets(const uint8_t *id, uint8_t n, int any)
{
	int b = BUCKET_NONE;
	uint8_t f;

	if (any)
		return BUCKET_NONE;
	for (f = 0; f < n; f++) {
		int this_b;

		this_b = bucket_of_format(id[f]);
		if (this_b == BUCKET_NONE)
			return BUCKET_NONE;
		if (b == BUCKET_NONE)
			b = this_b;
		else if (b != this_b)
			return BUCKET_NONE;
	}
	return b;
}

/* The targets one artefact names, as a presence set - ksigbuilder's own
 * bookkeeping for grouping and for naming a pack. It never goes on disk, which
 * is why 64 bits is room enough here while the pack carries a list. */
uint64_t ksb_target_set_of(const struct artefact *a)
{
	uint64_t set = 0;
	uint8_t i;

	if (a->any_target)
		return ~(uint64_t)0;
	for (i = 0; i < a->n_target; i++)
		if (a->target[i] < 64u)
			set |= (uint64_t)1 << a->target[i];
	return set;
}

/* Every field of the key, so the order is total and no two packs can tie. */
int ksb_group_cmp(const void *pa, const void *pb)
{
	const struct group *a = pa, *b = pb;

	if (a->kind != b->kind)
		return a->kind < b->kind ? -1 : 1;
	if (a->target_set != b->target_set)
		return a->target_set < b->target_set ? -1 : 1;
	if (a->arch_mask != b->arch_mask)
		return a->arch_mask < b->arch_mask ? -1 : 1;
	return 0;
}

int ksb_group_add(struct group *g, uint32_t idx)
{
	if (g->n == g->cap) {
		uint32_t nc = g->cap ? g->cap * 2 : 16;
		uint32_t *nv = realloc(g->member, nc * sizeof *nv);
		if (!nv)
			return 0;
		g->member = nv;
		g->cap = nc;
	}
	g->member[g->n++] = idx;
	return 1;
}

static const char *kind_name(uint32_t k)
{
	return k == KOF_PACK_UNPACK ? "unpack" : "sigs";
}

/* The word a pack's filename starts with, which is its kind and nothing
 * else. A similarity pack used to be spelled apart - see struct group. */
const char *ksb_group_name(const struct group *g)
{
	return kind_name(g->kind);
}

/*
 * NAMING A PACK SO A DIRECTORY LISTING IS READABLE.
 *
 * The name says WHAT IS IN THE PACK. It does not encode the key, and it used to:
 * "detect-t768-a0" spelled the masks in decimal, which nobody reads off a number,
 * and the numbers moved every time a format was added. Spelling the bits instead
 * fixed the reading and left the deeper mistake in place - the masks are already in
 * the pack header, per module and unioned, so a filename that repeats them is
 * carrying the machine's copy of something the machine already has.
 *
 * What a filename is for is telling a person which database this is, in ONE SHORT
 * GENERAL WORD. Not a list. A name assembled from its contents has no upper bound -
 * "zip+doczip" is two and looks survivable, fifty formats in a filename is where the
 * same rule ends up - and it churns every time a module is added to the pack.
 *
 * So: the general word is the format, and a label is used only where it is strictly
 * more informative and cannot grow. That is a pack holding exactly one module -
 * "upx-elf" says what "elf" does not, and there is nothing there to accumulate. The
 * moment a pack holds two, the format is the honest general answer and the labels
 * are not the filename's business; a reader who wants the roster opens the pack.
 *
 * The format word is likewise ONE format - the first the mask names, not the union.
 * ZIP|DOCZIP is "zip", because a DOCZIP is a zip and the extra bit is a distinction
 * the header already records exactly. The filename is the general answer; the pack
 * header is the precise one, and only one of them has to be both.
 *
 * THE ONE RULE THAT CANNOT BEND is that the name stays unique: two groups sharing a
 * filename means the second overwrites the first and half the database silently
 * disappears. Deriving the name from the key made that true by construction, and
 * that construction is exactly what produced names like "detect-t768-a0". Naming for
 * a reader gives the guarantee up, so it is CHECKED instead - see the refusal in the
 * write loop - and a collision stops the build rather than eating a pack.
 *
 * Deliberately in that order. A general name that collides is a build failure
 * somebody fixes in a minute; a precise name that nobody can read is permanent.
 *
 * Collisions can really happen, and now more easily: two packs whose masks differ
 * only in a bit past the first both want the same format word. That is a real
 * possibility rather than a hypothetical one, and it is the price of the general
 * name - paid at build time, loudly, by the person who can do something about it.
 */

/* Lowercased, with the word break a label carries turned into a hyphen and anything
 * else dropped: this becomes a path component on whatever filesystem the caller
 * chose. "upx_elf" is written "upx-elf"; a format name has no separator to convert. */
void ksb_name_append(char *out, size_t cap, size_t *at, const char *s)
{
	for (; *s && *at + 1u < cap; s++) {
		char c = *s;

		if (c >= 'A' && c <= 'Z')
			c = (char)(c + ('a' - 'A'));
		if (c == '_')
			c = '-';
		if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
		      c == '-'))
			continue;
		out[(*at)++] = c;
	}
	out[*at] = 0;
}

/*
 * The formats a mask names, joined - or "any" when it names all of them.
 *
 * Returns zero when the list would not fit, and the caller falls back to the mask
 * itself. Length rather than count is the test because format names differ in
 * length and a fixed count would sometimes fit and sometimes not.
 */
int ksb_format_list(uint64_t set, char *out, size_t cap)
{
	size_t at = 0;
	uint32_t f;

	out[0] = 0;
	if (set == ~(uint64_t)0) {
		ksb_name_append(out, cap, &at, "any");
		return 1;
	}
	for (f = 0; f < KOF_FMT_COUNT; f++) {
		if (!(set & ((uint64_t)1 << f)))
			continue;
		ksb_name_append(out, cap, &at, kof_format_name((uint8_t)f));
		return at != 0;
	}
	return 0;
}

/*
 * The label of a pack that holds exactly one module - which is its module's.
 *
 * Only one. A pack of two is not named by listing both: a name that grows with its
 * contents is the same mistake as spelling the mask, and it ends at fifty formats in
 * a filename. Two or more modules and the caller falls back to the format, which is
 * the general word that stays one word however many modules arrive.
 */
int ksb_label_one(const struct artefact *arts, const uint32_t *member,
		  uint32_t n, char *out, size_t cap)
{
	size_t at = 0;

	out[0] = 0;
	if (n != 1u)
		return 0;
	ksb_name_append(out, cap, &at, arts[member[0]].label);
	return at != 0;
}
