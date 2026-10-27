#define _GNU_SOURCE

/*
 * famcat.c - the malware family catalog. See famcat.h for the contract.
 */

#include <stdio.h>
#include <string.h>
#include <strings.h>

#include "../kofcore/kofmod/kofsig.h"   /* kof_maltype_name, KOF_MALTYPE_LIST */
#include "famcat.h"

void kof_famcat_init(struct kof_famcat *c, struct kof_famcat_fam *fam, uint32_t cap_fam,
		     struct kof_famcat_var *var, uint32_t cap_var)
{
	c->fam = fam;
	c->var = var;
	c->cap_fam = fam ? cap_fam : 0u;
	c->cap_var = var ? cap_var : 0u;
	c->n_fam = c->n_var = 0u;
	c->rev = 0u;
}

uint32_t kof_famcat_cap_family(const struct kof_famcat *c)
{
	return c->cap_fam;
}

uint32_t kof_famcat_cap_variant(const struct kof_famcat *c)
{
	return c->cap_var;
}

const char *kof_famcat_status_text(enum kof_famcat_status st)
{
	switch (st) {
	case KOF_FAMCAT_OK:         return "ok";
	case KOF_FAMCAT_EMPTY:      return "the name is empty";
	case KOF_FAMCAT_TOO_LONG:   return "name is over 63 characters";
	case KOF_FAMCAT_BAD_CHAR:   return "use letters, digits, _ and -";
	case KOF_FAMCAT_DUP_FAMILY: return "a family of that name exists";
	case KOF_FAMCAT_DUP_VARIANT: return "that variant name exists";
	case KOF_FAMCAT_BAD_TYPE:   return "that type is not selectable";
	case KOF_FAMCAT_FULL:       return "the catalog is full";
	case KOF_FAMCAT_NO_FAMILY:  return "no such family";
	case KOF_FAMCAT_NO_TYPE:    return "Select at least one Malware type";
	case KOF_FAMCAT_DUP_TYPES:  return "same types as another variant";
	case KOF_FAMCAT_VARIANT_NAME: return "family name too long (variants)";
	case KOF_FAMCAT_BAD_COMMENT: return "comment: no * or / and printable only";
	case KOF_FAMCAT_COMMENT_TOO_LONG: return "comment is over 120 characters";
	case KOF_FAMCAT_NO_FREE_LETTER: return "no deleted variant name to reuse";
	}
	return "unknown status";
}

enum kof_famcat_status kof_famcat_name_check(const char *name)
{
	if (!name || !name[0])
		return KOF_FAMCAT_EMPTY;
	if (strnlen(name, KOF_NAME_MAX + 1u) > KOF_NAME_MAX)
		return KOF_FAMCAT_TOO_LONG;
	return kof_name_ok(name) ? KOF_FAMCAT_OK : KOF_FAMCAT_BAD_CHAR;
}

enum kof_famcat_status kof_famcat_comment_check(const char *comment)
{
	size_t i;

	if (!comment)
		return KOF_FAMCAT_OK;
	if (strnlen(comment, KOF_FAMCAT_COMMENT_MAX + 1u) > KOF_FAMCAT_COMMENT_MAX)
		return KOF_FAMCAT_COMMENT_TOO_LONG;
	for (i = 0; comment[i]; i++)
		if (!kof_comment_char((unsigned char)comment[i]))
			return KOF_FAMCAT_BAD_COMMENT;
	return KOF_FAMCAT_OK;
}

static void comment_put(char *dst, const char *comment)
{
	memcpy(dst, comment ? comment : "", (comment ? strlen(comment) : 0u) + 1u);
}

/* ---- the types: the engine's list (KOF_MALTYPE_LIST) minus Packer --------------------------------------------- */

uint32_t kof_famcat_type_count(void)
{
	return (uint32_t)KOF_MALTYPE_COUNT - 1u;
}

/* The i-th value of the engine's list with Packer skipped, wherever the list puts it. */
uint32_t kof_famcat_type_value(uint32_t i)
{
	return i < (uint32_t)KOF_MALTYPE_PACKER ? i : i + 1u;
}

const char *kof_famcat_type_name(uint32_t i)
{
	return kof_maltype_name(kof_famcat_type_value(i));
}

uint32_t kof_famcat_type_mask_all(void)
{
	uint32_t m = 0u, i;

	for (i = 0; i < kof_famcat_type_count(); i++)
		m |= 1u << kof_famcat_type_value(i);
	return m;
}

/* ---- the operations --------------------------------------------------------------------------------------------- */

static int var_exists(const struct kof_famcat *c, const char *name)
{
	uint32_t i;

	for (i = 0; i < c->n_var; i++)
		if (!strcmp(c->var[i].name, name))
			return 1;
	return 0;
}

/* Is a family called `name` (letter case ignored: the name becomes a lower-case file name later) in the catalog, other than
 * `skip` (an index, or UINT32_MAX for none)? The one duplicate check of add_family and rename_family. */
static int family_taken(const struct kof_famcat *c, const char *name, uint32_t skip)
{
	uint32_t i;

	for (i = 0; i < c->n_fam; i++)
		if (i != skip && !strcasecmp(c->fam[i].name, name))
			return 1;
	return 0;
}

/* Letters of variant number n (1-based): bijective base 26, A..Z, AA..ZZ, AAA... The one place a variant name is spelt. */
static uint32_t letters_of(uint32_t n)
{
	uint32_t len = 0;

	for (; n; n = (n - 1u) / 26u)
		len++;
	return len ? len : 1u;
}

/* The letters of variant number n into out[cap]: the one spelling, used by the names and by the saved files. Returns their count,
 * 0 when n is 0 or they do not fit with the terminator. */
uint32_t kof_famcat_letter_text(uint32_t n, char *out, uint32_t cap)
{
	uint32_t len = letters_of(n), i;

	if (!n || len + 1u > cap)
		return 0u;
	out[len] = 0;
	for (i = len; i > 0; i--, n = (n - 1u) / 26u)
		out[i - 1u] = (char)('A' + (n - 1u) % 26u);
	return len;
}

/* "<family>_<letters of n>"; VARIANT_NAME when it is over KOF_FAMCAT_NAME_MAX or does not fit `cap`. */
static enum kof_famcat_status lettered(const char *family, uint32_t n, char *out, uint32_t cap)
{
	size_t fl = strlen(family);
	uint32_t len = letters_of(n);

	if (fl + 1u + len > KOF_FAMCAT_NAME_MAX || fl + 1u + len >= cap)
		return KOF_FAMCAT_VARIANT_NAME;
	memcpy(out, family, fl);
	out[fl] = '_';
	kof_famcat_letter_text(n, out + fl + 1u, len + 1u);
	return KOF_FAMCAT_OK;
}

/* The types a variant may carry: engine list only, and not empty. */
static enum kof_famcat_status types_check(uint32_t types)
{
	if (types & ~kof_famcat_type_mask_all())
		return KOF_FAMCAT_BAD_TYPE;
	return types ? KOF_FAMCAT_OK : KOF_FAMCAT_NO_TYPE;
}

/* Does a variant of `fam` other than `skip` (an index, or UINT32_MAX for none) have exactly this set? */
static int types_taken(const struct kof_famcat *c, uint32_t fam, uint32_t types, uint32_t skip)
{
	uint32_t i;

	for (i = 0; i < c->n_var; i++)
		if (i != skip && c->var[i].family == fam && c->var[i].types == types)
			return 1;
	return 0;
}

/* Does a variant of `fam` use letter number n? */
static int letter_used(const struct kof_famcat *c, uint32_t fam, uint32_t n)
{
	uint32_t i;

	for (i = 0; i < c->n_var; i++)
		if (c->var[i].family == fam && c->var[i].letter == n)
			return 1;
	return 0;
}

uint32_t kof_famcat_free_letters(const struct kof_famcat *c, uint32_t fam)
{
	uint32_t i, used = 0u;

	if (fam >= c->n_fam)
		return 0u;
	for (i = 0; i < c->n_var; i++)
		used += c->var[i].family == fam;
	return c->fam[fam].next - 1u - used;
}

/* The letter number the next variant of `fam` takes: the counter's, or with `reuse` the smallest below it no variant uses (0: none). */
static uint32_t next_letter(const struct kof_famcat *c, uint32_t fam, int reuse)
{
	uint32_t n;

	if (!reuse)
		return c->fam[fam].next;
	for (n = 1; n < c->fam[fam].next; n++)
		if (!letter_used(c, fam, n))
			return n;
	return 0u;
}

enum kof_famcat_status kof_famcat_variant_name(const struct kof_famcat *c, uint32_t fam, int reuse, char *out, uint32_t cap)
{
	uint32_t n;

	if (fam >= c->n_fam)
		return KOF_FAMCAT_NO_FAMILY;
	n = next_letter(c, fam, reuse);
	if (!n)
		return KOF_FAMCAT_NO_FREE_LETTER;
	return lettered(c->fam[fam].name, n, out, cap);
}

uint32_t kof_famcat_family_max(const struct kof_famcat *c)
{
	return KOF_NAME_MAX - 1u - letters_of(c->cap_var);
}

/* A family is accepted only if its longest possible variant name fits: the suffix of the last variant the table can hold. */
enum kof_famcat_status kof_famcat_first_variant_name(const struct kof_famcat *c, const char *family, char *out, uint32_t cap)
{
	if (strlen(family) > kof_famcat_family_max(c))
		return KOF_FAMCAT_VARIANT_NAME;
	return lettered(family, 1u, out, cap);
}

enum kof_famcat_status kof_famcat_add_family(struct kof_famcat *c, const char *name, const char *comment, uint32_t types,
					     uint32_t *fam)
{
	enum kof_famcat_status st = kof_famcat_name_check(name);
	char first[KOF_FAMCAT_NAME_MAX + 1];

	if (st != KOF_FAMCAT_OK)
		return st;
	if (family_taken(c, name, UINT32_MAX))
		return KOF_FAMCAT_DUP_FAMILY;
	st = kof_famcat_comment_check(comment);
	if (st != KOF_FAMCAT_OK)
		return st;
	st = types_check(types);
	if (st != KOF_FAMCAT_OK)
		return st;
	st = kof_famcat_first_variant_name(c, name, first, sizeof first);
	if (st != KOF_FAMCAT_OK)
		return st;
	if (c->n_fam >= c->cap_fam || c->n_var >= c->cap_var)
		return KOF_FAMCAT_FULL;
	if (var_exists(c, first))
		return KOF_FAMCAT_DUP_VARIANT;
	memcpy(c->fam[c->n_fam].name, name, strlen(name) + 1u);
	memcpy(c->var[c->n_var].name, first, strlen(first) + 1u);
	c->fam[c->n_fam].next = 2u;
	c->var[c->n_var].letter = 1u;
	comment_put(c->var[c->n_var].comment, comment);
	c->var[c->n_var].family = c->n_fam;
	c->var[c->n_var].types = types;
	if (fam)
		*fam = c->n_fam;
	c->n_fam++;
	c->n_var++;
	kof_famcat_touch(c);
	return KOF_FAMCAT_OK;
}

/* Add variant letter number n to family `fam`: the one code of add_variant (n from the counter or a reused letter) and of a loaded
 * file (n from the file). The counter never goes down; a letter at or above it moves it to n + 1. */
static enum kof_famcat_status put_variant(struct kof_famcat *c, uint32_t fam, uint32_t n, const char *comment, uint32_t types,
					  uint32_t *var)
{
	char name[KOF_FAMCAT_NAME_MAX + 1];
	enum kof_famcat_status st;

	if (fam >= c->n_fam)
		return KOF_FAMCAT_NO_FAMILY;
	st = lettered(c->fam[fam].name, n, name, sizeof name);
	if (st != KOF_FAMCAT_OK)
		return st;
	st = kof_famcat_comment_check(comment);
	if (st != KOF_FAMCAT_OK)
		return st;
	st = types_check(types);
	if (st != KOF_FAMCAT_OK)
		return st;
	if (types_taken(c, fam, types, UINT32_MAX))
		return KOF_FAMCAT_DUP_TYPES;
	if (c->n_var >= c->cap_var)
		return KOF_FAMCAT_FULL;
	if (letter_used(c, fam, n) || var_exists(c, name))
		return KOF_FAMCAT_DUP_VARIANT;
	memcpy(c->var[c->n_var].name, name, strlen(name) + 1u);
	comment_put(c->var[c->n_var].comment, comment);
	c->var[c->n_var].letter = n;
	if (n >= c->fam[fam].next)
		c->fam[fam].next = n + 1u;      /* a reused letter is below the counter, which never goes down */
	c->var[c->n_var].family = fam;
	c->var[c->n_var].types = types;
	if (var)
		*var = c->n_var;
	c->n_var++;
	kof_famcat_touch(c);
	return KOF_FAMCAT_OK;
}

enum kof_famcat_status kof_famcat_add_variant(struct kof_famcat *c, uint32_t fam, const char *comment, uint32_t types,
					      int reuse, uint32_t *var)
{
	char name[KOF_FAMCAT_NAME_MAX + 1];
	enum kof_famcat_status st = kof_famcat_variant_name(c, fam, reuse, name, sizeof name);

	if (st != KOF_FAMCAT_OK)
		return st;
	return put_variant(c, fam, next_letter(c, fam, reuse), comment, types, var);
}

/* ---- restoring a saved catalog (the loader's three steps) ------------------------------------------------------- */

enum kof_famcat_status kof_famcat_load_family(struct kof_famcat *c, const char *name, uint32_t *fam)
{
	enum kof_famcat_status st = kof_famcat_name_check(name);

	if (st != KOF_FAMCAT_OK)
		return st;
	if (family_taken(c, name, UINT32_MAX))
		return KOF_FAMCAT_DUP_FAMILY;
	if (strlen(name) > kof_famcat_family_max(c))
		return KOF_FAMCAT_VARIANT_NAME;
	if (c->n_fam >= c->cap_fam)
		return KOF_FAMCAT_FULL;
	memcpy(c->fam[c->n_fam].name, name, strlen(name) + 1u);
	c->fam[c->n_fam].next = 1u;
	if (fam)
		*fam = c->n_fam;
	c->n_fam++;
	kof_famcat_touch(c);
	return KOF_FAMCAT_OK;
}

enum kof_famcat_status kof_famcat_load_next(struct kof_famcat *c, uint32_t fam, uint32_t next)
{
	if (fam >= c->n_fam)
		return KOF_FAMCAT_NO_FAMILY;
	if (next < 1u || strlen(c->fam[fam].name) + 1u + letters_of(next) > KOF_FAMCAT_NAME_MAX)
		return KOF_FAMCAT_VARIANT_NAME;
	if (next > c->fam[fam].next)
		c->fam[fam].next = next;
	kof_famcat_touch(c);
	return KOF_FAMCAT_OK;
}

enum kof_famcat_status kof_famcat_load_variant(struct kof_famcat *c, uint32_t fam, uint32_t letter, const char *comment,
					       uint32_t types, uint32_t *var)
{
	return put_variant(c, fam, letter, comment, types, var);
}

/* The number of a letters suffix ("A" = 1, "Z" = 26, "AA" = 27): the way back of `lettered`. 0 when it is not 1..5 capital letters
 * (five keep the number far from the 32-bit limit; a name that long is refused by the 63-character rule anyway). */
uint32_t kof_famcat_letter_parse(const char *s)
{
	uint32_t n = 0u, i;

	if (!s || !s[0])
		return 0u;
	for (i = 0; s[i]; i++) {
		if (i >= 5u || s[i] < 'A' || s[i] > 'Z')
			return 0u;
		n = n * 26u + (uint32_t)(s[i] - 'A' + 1);
	}
	return n;
}

/* ---- the snapshot ----------------------------------------------------------------------------------------------- */

enum kof_famcat_status kof_famcat_snapshot(const struct kof_famcat *c, struct kof_famcat *snap)
{
	if (c->n_fam > snap->cap_fam || c->n_var > snap->cap_var)
		return KOF_FAMCAT_FULL;
	memcpy(snap->fam, c->fam, (size_t)c->n_fam * sizeof c->fam[0]);
	memcpy(snap->var, c->var, (size_t)c->n_var * sizeof c->var[0]);
	snap->n_fam = c->n_fam;
	snap->n_var = c->n_var;
	kof_famcat_touch(snap);
	return KOF_FAMCAT_OK;
}

enum kof_famcat_status kof_famcat_restore(struct kof_famcat *c, const struct kof_famcat *snap)
{
	return kof_famcat_snapshot(snap, c);
}

/* Compared by value, field by field: the bytes after a name's terminator are not part of the catalog. */
int kof_famcat_dirty(const struct kof_famcat *c, const struct kof_famcat *snap)
{
	uint32_t i;

	if (c->n_fam != snap->n_fam || c->n_var != snap->n_var)
		return 1;
	for (i = 0; i < c->n_fam; i++)
		if (c->fam[i].next != snap->fam[i].next || strcmp(c->fam[i].name, snap->fam[i].name))
			return 1;
	for (i = 0; i < c->n_var; i++)
		if (c->var[i].letter != snap->var[i].letter || c->var[i].family != snap->var[i].family ||
		    c->var[i].types != snap->var[i].types || strcmp(c->var[i].name, snap->var[i].name) ||
		    strcmp(c->var[i].comment, snap->var[i].comment))
			return 1;
	return 0;
}

/* The checks of a change to variant `var`: it exists, the types are allowed and no sibling has the set, the comment is allowed. */
static enum kof_famcat_status variant_check(const struct kof_famcat *c, uint32_t var, const char *comment, uint32_t types)
{
	enum kof_famcat_status st;

	if (var >= c->n_var)
		return KOF_FAMCAT_NO_FAMILY;
	st = types_check(types);
	if (st != KOF_FAMCAT_OK)
		return st;
	if (types_taken(c, c->var[var].family, types, var))
		return KOF_FAMCAT_DUP_TYPES;
	return kof_famcat_comment_check(comment);
}

enum kof_famcat_status kof_famcat_set_types(struct kof_famcat *c, uint32_t var, uint32_t types)
{
	enum kof_famcat_status st = variant_check(c, var, NULL, types);

	if (st != KOF_FAMCAT_OK)
		return st;
	c->var[var].types = types;
	kof_famcat_touch(c);
	return KOF_FAMCAT_OK;
}

enum kof_famcat_status kof_famcat_set_variant(struct kof_famcat *c, uint32_t var, const char *comment, uint32_t types)
{
	enum kof_famcat_status st = variant_check(c, var, comment, types);

	if (st != KOF_FAMCAT_OK)
		return st;
	c->var[var].types = types;
	comment_put(c->var[var].comment, comment);
	kof_famcat_touch(c);
	return KOF_FAMCAT_OK;
}

enum kof_famcat_status kof_famcat_rename_family(struct kof_famcat *c, uint32_t fam, const char *name)
{
	enum kof_famcat_status st;
	char first[KOF_FAMCAT_NAME_MAX + 1];
	size_t old;
	uint32_t i;

	if (fam >= c->n_fam)
		return KOF_FAMCAT_NO_FAMILY;
	st = kof_famcat_name_check(name);
	if (st != KOF_FAMCAT_OK)
		return st;
	if (family_taken(c, name, fam))
		return KOF_FAMCAT_DUP_FAMILY;
	st = kof_famcat_first_variant_name(c, name, first, sizeof first);
	if (st != KOF_FAMCAT_OK)
		return st;
	/* The longest suffix is the counter's, which deletes never lower. */
	if (strlen(name) + 1u + letters_of(c->fam[fam].next) > KOF_FAMCAT_NAME_MAX)
		return KOF_FAMCAT_VARIANT_NAME;
	/* A variant is "<family>_<letters>": the letters stay, the family part is the new name. */
	old = strlen(c->fam[fam].name);
	for (i = 0; i < c->n_var; i++)
		if (c->var[i].family == fam) {
			char suffix[KOF_FAMCAT_NAME_MAX + 1];

			memcpy(suffix, c->var[i].name + old, strlen(c->var[i].name + old) + 1u);
			memcpy(c->var[i].name, name, strlen(name));
			memcpy(c->var[i].name + strlen(name), suffix, strlen(suffix) + 1u);
		}
	memcpy(c->fam[fam].name, name, strlen(name) + 1u);
	kof_famcat_touch(c);
	return KOF_FAMCAT_OK;
}

/* Remove variant `var` from the table, the others keep their order. */
static void variant_remove(struct kof_famcat *c, uint32_t var)
{
	memmove(&c->var[var], &c->var[var + 1u], (size_t)(c->n_var - var - 1u) * sizeof c->var[0]);
	c->n_var--;
}

enum kof_famcat_status kof_famcat_delete_variant(struct kof_famcat *c, uint32_t var)
{
	if (var >= c->n_var)
		return KOF_FAMCAT_NO_FAMILY;
	variant_remove(c, var);
	kof_famcat_touch(c);
	return KOF_FAMCAT_OK;
}

enum kof_famcat_status kof_famcat_delete_family(struct kof_famcat *c, uint32_t fam)
{
	uint32_t i;

	if (fam >= c->n_fam)
		return KOF_FAMCAT_NO_FAMILY;
	for (i = c->n_var; i > 0; i--)
		if (c->var[i - 1u].family == fam)
			variant_remove(c, i - 1u);
	for (i = 0; i < c->n_var; i++)
		if (c->var[i].family > fam)
			c->var[i].family--;
	memmove(&c->fam[fam], &c->fam[fam + 1u], (size_t)(c->n_fam - fam - 1u) * sizeof c->fam[0]);
	c->n_fam--;
	kof_famcat_touch(c);
	return KOF_FAMCAT_OK;
}

enum kof_famcat_status kof_famcat_set_comment(struct kof_famcat *c, uint32_t var, const char *comment)
{
	enum kof_famcat_status st = variant_check(c, var, comment, var < c->n_var ? c->var[var].types : 0u);

	if (st != KOF_FAMCAT_OK)
		return st;
	comment_put(c->var[var].comment, comment);
	kof_famcat_touch(c);
	return KOF_FAMCAT_OK;
}

const char *kof_famcat_comment(const struct kof_famcat *c, uint32_t var)
{
	return var < c->n_var ? c->var[var].comment : "";
}

uint32_t kof_famcat_list(const struct kof_famcat *c, struct kof_famcat_item *out, uint32_t cap)
{
	uint32_t f, v, n = 0u;

	for (f = 0; f < c->n_fam; f++) {
		if (n < cap) {
			out[n].family = f;
			out[n].variant = -1;
		}
		n++;
		for (v = 0; v < c->n_var; v++) {
			if (c->var[v].family != f)
				continue;
			if (n < cap) {
				out[n].family = f;
				out[n].variant = (int32_t)v;
			}
			n++;
		}
	}
	return n;
}
