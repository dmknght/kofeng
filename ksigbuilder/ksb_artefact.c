/*
 * ksb_artefact.c - PACK: one artefact set read back from disk, and what
 *    identifies it.
 */

#include "ksb.h"


#include <kofcmp.h>

#include <databases/dbpacker.h>

/* ============================================================================
 * PACK - gather compiled artefacts into .ksig
 * ============================================================================ */

void ksb_artefact_free(struct artefact *a)
{
	free(a->stem);
	free(a->label);
	free(a->srcpath);
	free(a->family);
	free(a->content);
	free(a->code);
	free(a->str);
	free(a->rng);
	free(a->blk);
	free(a->pool);
	free(a->name);
	free(a->str_bytes);
	free(a->name_text);
	/*
	 * Cleared, so freeing twice is harmless rather than merely unreached.
	 *
	 * Today it is unreached: the one caller that frees a half loaded artefact
	 * has not incremented the count yet, so the sweep at the end skips the slot
	 * it freed. That is a fact about an index, not about this function, and the
	 * next person to move an increment does not know it. Eight stores make the
	 * question stop existing.
	 */
	memset(a, 0, sizeof *a);
}

/*
 * The .meta record. Mandatory, and so is every field it must carry.
 *
 * The loader can afford a permissive default for a missing field because a wrong
 * guess there costs scan time. A wrong guess here is baked into a database and
 * costs detections, so there are no defaults: an incomplete record is a build that
 * went wrong and the only useful thing to do with it is stop.
 */
static int meta_load(struct artefact *a)
{
	/* Sized for the longest VALUE, not just the numeric fields: srcpath= can
	 * be a deep bases-tree path, and at line[128] fgets split it, the tail
	 * matched no key and was dropped, and the recorded source was truncated.
	 * names_load sizes its buffer the same way and for the same reason. */
	char *path = ksb_sibling(a->stem, ".meta"), line[KOF_NAME_MAX_LEN + 64];
	FILE *f;
	uint64_t blob_len = 0;
	int have_target = 0, have_kind = 0, ok = 0;

	if (!path)
		return 0;
	f = fopen(path, "r");
	if (!f) {
		fprintf(stderr, "ksigbuilder: %s: no record beside the blob\n",
			a->stem);
		goto out;
	}
	while (fgets(line, sizeof line, f)) {
		if (strncmp(line, "target=", 7) == 0) {
			/* "4,8,9", or empty for a module that named
			 * everything - see ksb_target_text. */
			char *q = line + 7;

			a->n_target = 0;
			while (*q && *q != '\n') {
				if (*q < '0' || *q > '9') {
					q++;
					continue;
				}
				if (a->n_target >= KOF_TARGET_LIST_MAX)
					break;
				a->target[a->n_target++] =
					(uint8_t)strtoul(q, &q, 10);
			}
			have_target = 1;
		} else if (strncmp(line, "anytarget=", 10) == 0) {
			a->any_target = atoi(line + 10) != 0;
		} else if (strncmp(line, "scan_mask=", 10) == 0) {
			a->scan_mask = (uint32_t)strtoul(line + 10, 0, 10);
		} else if (strncmp(line, "size_min=", 9) == 0) {
			a->size_min = strtoull(line + 9, 0, 10);
		} else if (strncmp(line, "arch_mask=", 10) == 0) {
			a->arch_mask = (uint32_t)strtoul(line + 10, 0, 10);
		} else if (strncmp(line, "subtype_mask=", 13) == 0) {
			a->subtype_mask = (uint32_t)strtoul(line + 13, 0, 10);
		} else if (strncmp(line, "step=", 5) == 0) {
			a->step = (uint32_t)strtoul(line + 5, 0, 10);
		} else if (strncmp(line, "blob_len=", 9) == 0) {
			blob_len = strtoull(line + 9, 0, 10);
		} else if (strncmp(line, "kind=", 5) == 0) {
			a->kind = (uint32_t)strtoul(line + 5, 0, 10);
			have_kind = 1;
		} else if (strncmp(line, "srcpath=", 8) == 0) {
			/* The newline, like every other text field here. Left
			 * on, it goes into the name pool with the string and
			 * the entry runs into the one after it: the path came
			 * back as "signatures/x.c\np1tox" and opened nothing. */
			char *nl = strchr(line + 8, '\n');

			if (nl)
				*nl = 0;
			free(a->srcpath);
			a->srcpath = strdup(line + 8);
			if (!a->srcpath) {
				fclose(f);
				goto out;
			}
		} else if (strncmp(line, "label=", 6) == 0) {
			char *nl = strchr(line + 6, '\n');

			if (nl)
				*nl = 0;
			free(a->label);
			a->label = strdup(line + 6);
			if (!a->label) {
				fclose(f);
				goto out;
			}
		} else if (strncmp(line, "family=", 7) == 0) {
			char *nl = strchr(line + 7, '\n');

			if (nl)
				*nl = 0;
			free(a->family);
			a->family = strdup(line + 7);
			if (!a->family) {
				fclose(f);
				goto out;
			}
		} else if (strncmp(line, "maltype=", 8) == 0) {
			a->maltype = (uint32_t)strtoul(line + 8, 0, 10);
		} else if (strncmp(line, "content=", 8) == 0) {
			char *nl = strchr(line + 8, '\n');

			if (nl)
				*nl = 0;
			free(a->content);
			/* Empty stays NULL: nothing declared must not intern a
			 * zero-length word. */
			a->content = line[8] ? strdup(line + 8) : NULL;
			if (line[8] && !a->content) {
				fclose(f);
				goto out;
			}
		}
	}
	fclose(f);

	/* An empty list is only legal when the module SAID everything: "any"
	 * and "nothing was declared" are the same zero, and one of them is a
	 * source that forgot KOF_TARGET_FORMAT. */
	if (!have_target || (a->n_target == 0 && !a->any_target)) {
		fprintf(stderr, "ksigbuilder: %s: record declares no target\n",
			a->stem);
		goto out;
	}
	if (!have_kind) {
		fprintf(stderr, "ksigbuilder: %s: record declares no kind\n",
			a->stem);
		goto out;
	}
	/* Required rather than defaulted. A missing label means the artefact was
	 * written by an older compiler, and guessing one from the path would name a
	 * pack after a guess - which is the one thing a name in a directory listing
	 * must never be. Rebuilding the artefacts fixes it. */
	if (!a->label || !a->label[0]) {
		fprintf(stderr, "ksigbuilder: %s: record declares no label; "
				"rebuild the artefacts\n", a->stem);
		goto out;
	}
	/* Same reasoning as label just above: a detect-kind module always has a
	 * KOF_TARGET_NAME (the build's --extract refuses the source
	 * otherwise), so an empty family here means an artefact from before
	 * this field existed, not a module that legitimately has none. */
	if (a->kind == KOF_PACK_DETECT && (!a->family || !a->family[0])) {
		fprintf(stderr, "ksigbuilder: %s: record declares no family; "
				"rebuild the artefacts\n", a->stem);
		goto out;
	}
	if (a->kind != KOF_PACK_DETECT && a->kind != KOF_PACK_UNPACK) {
		fprintf(stderr, "ksigbuilder: %s: unknown kind %u\n", a->stem,
			a->kind);
		goto out;
	}
	if (blob_len != a->code_len) {
		fprintf(stderr, "ksigbuilder: %s: blob is %u bytes, record says "
				"%llu\n", a->stem, a->code_len,
			(unsigned long long)blob_len);
		goto out;
	}
	ok = 1;
out:
	free(path);
	return ok;
}

/* id<TAB>text per line. Absent is allowed: a module may report nothing by name. */
static int names_load(struct artefact *a)
{
	/* Sized from the name limit plus the id column, so a legal name can never be
	 * split across two reads - which is how ".Variant" used to disappear. */
	char *path = ksb_sibling(a->stem, ".names"), line[KOF_NAME_MAX_LEN + 64];
	FILE *f;
	size_t text_cap = 0, text_len = 0;
	uint32_t cap = 0, i;
	int ok = 0;

	if (!path)
		return 0;
	f = fopen(path, "r");
	if (!f) {
		ok = 1;                  /* nothing to report by name */
		goto out;
	}
	while (fgets(line, sizeof line, f)) {
		char *tab = strchr(line, '\t'), *nl;
		size_t tl;

		if (!tab)
			continue;
		*tab++ = 0;
		nl = strchr(tab, '\n');
		if (nl)
			*nl = 0;
		tl = strlen(tab) + 1;

		if (text_len > text_cap || tl > text_cap - text_len) {
			size_t nc = text_cap ? text_cap * 2 : 512;
			char *nt;
			/* Ceiling as above. */
			while (nc < text_len + tl) {
				if (nc > (size_t)-1 / 2u)
					goto out;
				nc *= 2;
			}
			nt = realloc(a->name_text, nc);
			if (!nt)
				goto out;
			a->name_text = nt;
			text_cap = nc;
		}
		if (a->n_names == cap) {
			uint32_t nc = cap ? cap * 2 : 8;
			struct kof_pw_name *nv = realloc(a->name, nc * sizeof *nv);
			if (!nv)
				goto out;
			a->name = nv;
			cap = nc;
		}
		memcpy(a->name_text + text_len, tab, tl);
		/* An offset now, a pointer once the buffer stops moving: it is
		 * reallocated as it grows, so a pointer taken here would dangle. */
		a->name[a->n_names].id   = (uint32_t)strtoul(line, 0, 10);
		a->name[a->n_names].text = (const char *)(uintptr_t)text_len;
		a->n_names++;
		text_len += tl;
	}
	fclose(f);
	for (i = 0; i < a->n_names; i++)
		a->name[i].text = a->name_text + (uintptr_t)a->name[i].text;
	ok = 1;
out:
	free(path);
	return ok;
}

/*
 * What the string rows accumulate while they are read: how much of each of the
 * artefact's growing arrays is allocated and how much is used. The arrays
 * themselves are the artefact's.
 */
struct strs_acc {
	size_t   bytes_cap, bytes_len;   /* a->str_bytes */
	uint32_t scap, rcap;             /* a->str, a->rng, in elements */
};

/*
 * Read `want` tab separated numeric columns from *pp, the row's text after its
 * kind column, ending each at its tab. Returns how many were there; *pp is left
 * after the last one read.
 */
static unsigned strs_cols(char **pp, unsigned long *v, unsigned want)
{
	char *p = *pp, *tab;
	unsigned k;

	for (k = 0; k < want; k++) {
		tab = strchr(p, '\t');
		if (!tab)
			break;
		*tab = 0;
		v[k] = strtoul(p, 0, 10);
		p = tab + 1;
	}
	*pp = p;
	return k;
}

/* Room in a->str_bytes for `len` more bytes. Zero when there is none. */
static int strs_room_bytes(struct artefact *a, struct strs_acc *acc,
			   unsigned long len)
{
	if (acc->bytes_len > acc->bytes_cap ||
	    len > acc->bytes_cap - acc->bytes_len) {
		size_t nc = acc->bytes_cap ? acc->bytes_cap * 2 : 1024;
		uint8_t *nb;
		/* The doubling needs the ceiling, not just the
		 * test: nc past half of size_t doubles to zero
		 * and the loop then exits SATISFIED. */
		while (nc < acc->bytes_len + len) {
			if (nc > (size_t)-1 / 2u)
				return 0;
			nc *= 2;
		}
		nb = realloc(a->str_bytes, nc);
		if (!nb)
			return 0;
		a->str_bytes = nb;
		acc->bytes_cap = nc;
	}
	return 1;
}

/* Room for one more entry in a->str. Zero when there is none. */
static int strs_room_str(struct artefact *a, struct strs_acc *acc)
{
	if (a->n_str == acc->scap) {
		uint32_t nc = acc->scap ? acc->scap * 2 : 8;
		struct kof_pw_str *nv = realloc(a->str, nc * sizeof *nv);

		if (!nv)
			return 0;
		a->str = nv;
		acc->scap = nc;
	}
	return 1;
}

/*
 * Record the string whose `len` bytes are now at a->str_bytes + acc->bytes_len.
 * The pointer is an offset until the whole file is read - the buffer moves as it
 * grows - and strs_load turns them into pointers at the end.
 */
static void strs_push(struct artefact *a, struct strs_acc *acc,
		      unsigned long len, uint8_t kind, uint8_t flags)
{
	a->str[a->n_str].bytes = (const uint8_t *)(uintptr_t)acc->bytes_len;
	a->str[a->n_str].len   = (uint16_t)len;
	a->str[a->n_str].kind  = kind;
	a->str[a->n_str].flags = flags;
	a->n_str++;
	acc->bytes_len += len;
}

/* r <id> <mask> */
static int strs_row_range(struct artefact *a, struct strs_acc *acc, char *p)
{
	char *tab = strchr(p, '\t');

	if (!tab)
		return 1;
	if (a->n_rng == acc->rcap) {
		uint32_t nc = acc->rcap ? acc->rcap * 2 : 8;
		uint32_t *nv = realloc(a->rng, nc * sizeof *nv);
		if (!nv)
			return 0;
		a->rng = nv;
		acc->rcap = nc;
	}
	a->rng[a->n_rng++] = (uint32_t)strtoul(tab + 1, 0, 10);
	return 1;
}

/* b <id> <mask> <norm> <side> <n> <hashes, 8 hex each> */
static int strs_row_block(struct artefact *a, char *p)
{
	unsigned long v[4];
	char *hex, *tab;
	uint32_t k;
	struct kof_mutation_block *nb;
	uint32_t *np;

	if (strs_cols(&p, v, 4u) != 4u)
		return 1;
	tab = strchr(p, '\t');
	if (!tab)
		return 1;
	*tab = 0;
	{
		unsigned long n_hash = strtoul(p, 0, 10);

		hex = tab + 1;
		if (n_hash < KGENOME_MUTATION_MIN_HASH ||
		    n_hash > KOF_MUTATION_MAX_HASH ||
		    strlen(hex) < n_hash * 8u)
			return 0;
		nb = realloc(a->blk, (a->n_blk + 1u) * sizeof *nb);
		if (!nb)
			return 0;
		a->blk = nb;
		np = realloc(a->pool,
			     (a->n_pool + n_hash) * sizeof *np);
		if (!np)
			return 0;
		a->pool = np;

		nb = &a->blk[a->n_blk];
		memset(nb, 0, sizeof *nb);
		nb->first_hash = a->n_pool;
		nb->n_hash = (uint32_t)n_hash;
		nb->scan_mask = (uint32_t)v[1];
		nb->norm = (uint8_t)v[2];
		nb->side = (uint8_t)v[3];
		for (k = 0; k < n_hash; k++) {
			char one[9];

			memcpy(one, hex + k * 8u, 8u);
			one[8] = 0;
			a->pool[a->n_pool + k] =
				(uint32_t)strtoul(one, 0, 16);
		}
		a->n_pool += (uint32_t)n_hash;
		a->n_blk++;
	}
	return 1;
}

/* s <id> <icase> <fullword> <len> <literal> */
static int strs_row_string(struct artefact *a, struct strs_acc *acc, char *p)
{
	unsigned long v[4], icase, fullw, len;
	char *lit;
	size_t actual;

	if (strs_cols(&p, v, 4u) != 4u) {
		fprintf(stderr, "ksigbuilder: %s: malformed string "
				"row\n", a->stem);
		return 0;
	}
	icase = v[1];
	fullw = v[2];
	len   = v[3];
	lit   = p;

	actual = strlen(lit);
	while (actual && (lit[actual - 1] == '\n' ||
			  lit[actual - 1] == '\r'))
		lit[--actual] = 0;

	/* The recorded length is authoritative - it is what the
	 * pattern compiler measured. Disagreeing with it is a
	 * build that went wrong, not a row to skip. */
	if (len == 0 || len > KOF_STR_MAX_LEN || actual != len) {
		fprintf(stderr, "ksigbuilder: %s: string of declared "
				"length %lu does not match its "
				"literal\n", a->stem, len);
		return 0;
	}
	if (!strs_room_bytes(a, acc, len) || !strs_room_str(a, acc))
		return 0;
	memcpy(a->str_bytes + acc->bytes_len, lit, len);
	strs_push(a, acc, len, KOF_STR_LITERAL, (uint8_t)
		  ((icase ? KOF_STR_ICASE : 0u) |
		   (fullw == 1 ? KOF_STR_FULLWORD :
		    fullw == 2 ? KOF_STR_TOKEN : 0u)));
	return 1;
}

/* w <id> <icase> <fullword> <wide> <len> <literal as hex digits> - a literal
 * whose bytes cannot go in a text column. Same meaning as an 's' row in every
 * other respect. */
static int strs_row_wide(struct artefact *a, struct strs_acc *acc, char *p)
{
	unsigned long v[5], icase, fullw, wide, len;
	char *end;
	uint32_t k2;

	if (strs_cols(&p, v, 5u) != 5u) {
		fprintf(stderr, "ksigbuilder: %s: malformed wide "
				"string row\n", a->stem);
		return 0;
	}
	icase = v[1];
	fullw = v[2];
	wide  = v[3];
	len   = v[4];
	if (len == 0 || len > KOF_STR_MAX_LEN) {
		fprintf(stderr, "ksigbuilder: %s: literal of "
				"length %lu\n", a->stem, len);
		return 0;
	}
	for (end = p; *end && *end != '\n' && *end != '\r'; end++)
		;
	if ((size_t)(end - p) != len * 2) {
		fprintf(stderr, "ksigbuilder: %s: literal says "
				"%lu bytes and carries %u\n",
			a->stem, len,
			(unsigned)((end - p) / 2));
		return 0;
	}
	if (!strs_room_bytes(a, acc, len) || !strs_room_str(a, acc))
		return 0;
	for (k2 = 0; k2 < len; k2++) {
		char h[3];

		h[0] = p[k2 * 2u];
		h[1] = p[k2 * 2u + 1u];
		h[2] = 0;
		a->str_bytes[acc->bytes_len + k2] =
			(uint8_t)strtoul(h, 0, 16);
	}
	strs_push(a, acc, len, KOF_STR_LITERAL, (uint8_t)
		  ((icase ? KOF_STR_ICASE : 0u) |
		   (fullw == 1 ? KOF_STR_FULLWORD :
		    fullw == 2 ? KOF_STR_TOKEN : 0u) |
		   (wide  ? KOF_STR_WIDE     : 0u)));
	return 1;
}

/* h <id> <case option> <word option> <len> <program as hex digits> */
static int strs_row_hex(struct artefact *a, struct strs_acc *acc, char *p)
{
	unsigned long len, hic = 0, hfw = 0;
	char *end, *tab;
	uint32_t k;

	tab = strchr(p, '\t');       /* past the id column */
	if (!tab)
		return 1;
	p = tab + 1;
	tab = strchr(p, '\t');       /* the case option */
	if (!tab)
		return 1;
	hic = strtoul(p, 0, 10);
	p = tab + 1;
	tab = strchr(p, '\t');       /* the word option */
	if (!tab)
		return 1;
	hfw = strtoul(p, 0, 10);
	p = tab + 1;
	tab = strchr(p, '\t');
	if (!tab)
		return 1;
	len = strtoul(p, 0, 10);
	p = tab + 1;                 /* the digits */
	if (len == 0 || len > KOF_HEX_MAX_PROG) {
		fprintf(stderr, "ksigbuilder: %s: hex program of "
				"length %lu\n", a->stem, len);
		return 0;
	}
	for (end = p; *end && *end != '\n' && *end != '\r'; end++)
		;
	if ((size_t)(end - p) != len * 2) {
		fprintf(stderr, "ksigbuilder: %s: hex program says "
				"%lu bytes but carries %zu digits\n",
			a->stem, len, (size_t)(end - p));
		return 0;
	}
	if (!strs_room_bytes(a, acc, len) || !strs_room_str(a, acc))
		return 0;
	for (k = 0; k < (uint32_t)len; k++) {
		unsigned v;
		if (sscanf(p + k * 2, "%2x", &v) != 1) {
			fprintf(stderr, "ksigbuilder: %s: malformed "
					"hex program\n", a->stem);
			return 0;
		}
		a->str_bytes[acc->bytes_len + k] = (uint8_t)v;
	}
	strs_push(a, acc, len, KOF_STR_HEX, (uint8_t)
		  ((hic ? KOF_STR_ICASE : 0u) |
		   (hfw == 1 ? KOF_STR_FULLWORD :
		    hfw == 2 ? KOF_STR_TOKEN : 0u)));
	return 1;
}

/*
 * Declared strings and ranges. Tab separated, kind in column one: 'r' for a range
 * mask, 's' for a string with the literal last so nothing in it needs escaping to
 * keep the earlier columns parseable.
 */
static int strs_load(struct artefact *a)
{
	char *path = ksb_sibling(a->stem, ".strs"), line[2 * KOF_HEX_MAX_PROG + 128];
	FILE *f;
	struct strs_acc acc = { 0, 0, 0, 0 };
	uint32_t i;
	int ok = 0;

	if (!path)
		return 0;
	f = fopen(path, "r");
	if (!f) {
		ok = 1;                  /* a module may declare neither */
		goto out;
	}
	while (fgets(line, sizeof line, f)) {
		char *p = line;
		int row_ok = 1;

		if (p[0] == 'r' && p[1] == '\t')
			row_ok = strs_row_range(a, &acc, p + 2);
		else if (p[0] == 'b' && p[1] == '\t')
			row_ok = strs_row_block(a, p + 2);
		else if (p[0] == 's' && p[1] == '\t')
			row_ok = strs_row_string(a, &acc, p + 2);
		else if (p[0] == 'w' && p[1] == '\t')
			row_ok = strs_row_wide(a, &acc, p + 2);
		else if (p[0] == 'h' && p[1] == '\t')
			row_ok = strs_row_hex(a, &acc, p + 2);
		if (!row_ok)
			goto out;
	}
	fclose(f);
	for (i = 0; i < a->n_str; i++)
		a->str[i].bytes = a->str_bytes + (uintptr_t)a->str[i].bytes;
	ok = 1;
out:
	free(path);
	return ok;
}

/* By artefact name - the flattened path below the content tree, which is unique
 * by construction and stable across machines. */
int ksb_artefact_cmp(const void *a, const void *b)
{
	const struct artefact *x = (const struct artefact *)a;
	const struct artefact *y = (const struct artefact *)b;

	return strcmp(x->stem ? x->stem : "", y->stem ? y->stem : "");
}

int ksb_artefact_load(struct artefact *a, const char *blob_path)
{
	size_t n = strlen(blob_path), len = 0;

	memset(a, 0, sizeof *a);
	/* n - 5 is a subtraction on a length this function did not check. The
	 * only caller rejects a name shorter than ".blob" plus one, so it
	 * cannot be reached today - but the guard belongs where the arithmetic
	 * is, not one function away where a second caller would not see it. */
	if (n < 6u)
		return 0;
	a->stem = malloc(n - 5 + 1);
	if (!a->stem)
		return 0;
	memcpy(a->stem, blob_path, n - 5);
	a->stem[n - 5] = 0;

	a->code = ksb_read_whole(blob_path, KOF_BLOB_MAX_CODE, &len);
	if (!a->code) {
		fprintf(stderr, "ksigbuilder: cannot read %s\n", blob_path);
		return 0;
	}
	/* The same guard the loader applies, applied where a failure is a build
	 * failure rather than something a customer's machine discovers. */
	if (len >= 4 && memcmp(a->code, "\177ELF", 4) == 0) {
		fprintf(stderr, "ksigbuilder: %s is an ELF image, not a blob\n",
			blob_path);
		return 0;
	}
	a->code_len = (uint32_t)len;

	return meta_load(a) && names_load(a) && strs_load(a);
}

/*
 * A fingerprint of everything that decides whether this module fires: its
 * preconditions, and the exact set of patterns and regions it searches for - not
 * its code, so two modules that reach the same verdict by different logic are not
 * "the same signature" and this does not claim they are. That is a real limitation,
 * not an oversight: a module whose kof_scan body does something beyond calling
 * kof_find_str_* is invisible to this check.
 *
 * Order independent by construction: each string and each range hashes to one
 * number of its own, and the SORTED list of those numbers is what gets hashed
 * again - so two artefacts differing only in which order their declarations were
 * typed in still fingerprint the same, which is the case this exists to catch.
 */
static uint32_t artefact_fingerprint(const struct artefact *a)
{
	uint32_t *sh = NULL, *rh = NULL;
	uint32_t i, precond[4], final = 0;
	uint8_t *buf;
	size_t buflen, w;

	if (a->n_str) {
		sh = malloc(a->n_str * sizeof *sh);
		if (!sh)
			return 0;
	}
	if (a->n_rng) {
		rh = malloc(a->n_rng * sizeof *rh);
		if (!rh) {
			free(sh);
			return 0;
		}
	}

	for (i = 0; i < a->n_str; i++) {
		uint32_t hh = KOF_HASH_INIT;
		uint32_t j;

		hh = kof_hash_step(hh, a->str[i].kind);
		hh = kof_hash_step(hh, a->str[i].flags);
		for (j = 0; j < a->str[i].len; j++)
			hh = kof_hash_step(hh, a->str[i].bytes[j]);
		sh[i] = hh;
	}
	for (i = 0; i < a->n_rng; i++)
		rh[i] = a->rng[i];

	if (a->n_str)
		qsort(sh, a->n_str, sizeof *sh, kof_cmp_u32);
	if (a->n_rng)
		qsort(rh, a->n_rng, sizeof *rh, kof_cmp_u32);

	/* The targets as the SET they are: the fingerprint has to be the same
	 * for two artefacts that fire on the same things, and a set is order
	 * independent where the list as written is not. */
	precond[0] = (uint32_t)ksb_target_set_of(a) ^
		     (uint32_t)(ksb_target_set_of(a) >> 32);
	precond[1] = a->subtype_mask;
	precond[2] = a->arch_mask;
	precond[3] = (uint32_t)a->size_min;   /* truncated on purpose - a size floor
						* that differs only past 4GB is not
						* worth splitting a fingerprint over */

	buflen = sizeof precond + (size_t)a->n_str * sizeof *sh +
		 (size_t)a->n_rng * sizeof *rh;
	buf = malloc(buflen);
	if (!buf) {
		free(sh);
		free(rh);
		return 0;
	}
	w = 0;
	memcpy(buf + w, precond, sizeof precond);
	w += sizeof precond;
	if (a->n_str) {
		memcpy(buf + w, sh, (size_t)a->n_str * sizeof *sh);
		w += (size_t)a->n_str * sizeof *sh;
	}
	if (a->n_rng)
		memcpy(buf + w, rh, (size_t)a->n_rng * sizeof *rh);

	final = kof_hash_bytes(buf, buflen);
	free(buf);
	free(sh);
	free(rh);
	return final;
}

struct fp_idx {
	uint32_t fp;
	uint32_t idx;
};

static int cmp_fp_idx(const void *pa, const void *pb)
{
	const struct fp_idx *a = pa, *b = pb;
	return a->fp < b->fp ? -1 : (a->fp > b->fp ? 1 : 0);
}

/*
 * Warn, do not refuse: a real collision means two artefacts declare the same
 * target, region and pattern set, which is either a copy left behind or two
 * families that genuinely share one detection - and only a person reading both
 * files can tell which. Refusing the build over the second case would make a
 * legitimate database impossible to build; staying quiet about the first lets a
 * stale duplicate ride along indefinitely. A warning is the one answer that costs
 * nothing when it is the second case and loses nothing when it is the first.
 */
void ksb_warn_duplicate_patterns(struct artefact *arts, uint32_t n_arts)
{
	struct fp_idx *fps;
	uint32_t i;

	if (n_arts < 2)
		return;
	fps = malloc(n_arts * sizeof *fps);
	if (!fps)
		return;
	for (i = 0; i < n_arts; i++) {
		arts[i].fp = artefact_fingerprint(&arts[i]);
		fps[i].fp = arts[i].fp;
		fps[i].idx = i;
	}
	qsort(fps, n_arts, sizeof *fps, cmp_fp_idx);
	for (i = 0; i + 1 < n_arts; i++) {
		if (fps[i].fp != fps[i + 1].fp)
			continue;
		/*
		 * ACROSS KINDS IT IS NOT A DUPLICATE, IT IS A PAIR. The two say
		 * different things about the same kind of file and neither is
		 * redundant. Only two modules of the SAME kind saying it are
		 * worth a word.
		 */
		if (arts[fps[i].idx].kind != arts[fps[i + 1].idx].kind)
			continue;
		/*
		 * A MODULE THAT DECLARES NO PATTERN IS NOT COMPARABLE.
		 *
		 * The fingerprint is target, regions and patterns, so with no
		 * patterns it is only the target - and every unpacker for one
		 * format then collides with every other. The four msfvenom
		 * decoders are the case: each recognises its stub by comparing
		 * bytes inside kof_unpack, which is code and not a declaration,
		 * so all four fingerprint identically and none is redundant.
		 * Saying so anyway trains a reader to ignore the warning, which
		 * costs the one time it is real.
		 */
		if (!arts[fps[i].idx].n_str && !arts[fps[i + 1].idx].n_str)
			continue;
		fprintf(stderr,
			"ksigbuilder: warning: %s and %s have the same target, "
			"region and patterns\n",
			arts[fps[i].idx].stem, arts[fps[i + 1].idx].stem);
	}
	free(fps);
}
