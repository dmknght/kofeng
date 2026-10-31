#ifndef KOF_CATNAMES_H
#define KOF_CATNAMES_H

/*
 * catnames.h - THE NAMES OF THE CATALOG IDS, held by an engine so a verdict can say "Mirai.A" and not "F8f3a51c2.V2c61b7e0".
 *
 * A database carries the names of the ids its diagnoses use in names.kdig (kof_db_load_names, behind the fallback below); a host that keeps the
 * catalogs may also hand the engine the two catalog directories (keng_catalog_load, kofeng.h), which answer first: <bases>/pathogens (families and variants)
 * and <bases>/syndromes (tags). The engine reads them with the catalogs' own loaders (famcat.h, tagcat.h: no second reader) and
 * keeps an id -> name table of its own, one per engine, no global.
 *
 * MEMORY. The table is charged to the engine's budget (kofbudget.h) as the database is: it is asked for before it is allocated, taken
 * for good when it is built and given back with it. It starts small and doubles while files are still refused for want of room, and
 * stops at the smaller of KOF_CATNAMES_MAX_BYTES and an eighth of what the budget has left. What did not fit is NOT silent: the status
 * says OVER_BUDGET with the number of files not read, and every id of an unread file is spelled in hex exactly as with no catalog.
 *
 * SPELLING. Everything that turns an id into text goes through this file's *_text functions, so the verdict (verdict.c), kofscanner's
 * listing and the viewer cannot drift: a family id and a variant id are "<Family>.<Letters>" ("Mirai.A"), a tag id is its name; an id
 * the catalog does not hold keeps the hex spelling of kverdict_catalog_word, in the verdict with the prefix it always had (F, V, T) so
 * that a named and an unnamed part are never mistaken for each other. A catalog name is checked again here (the name rule of its
 * kind) before it is used in a verdict: a character that is a separator of the verdict ('#', '/', ':', '!', '?', '.') cannot reach it.
 */

#include <stddef.h>
#include <stdint.h>

struct kof_budget;
struct kof_catnames;
typedef struct kof_catnames kof_catnames;

/* The most one engine's names may take, whatever the budget has left. */
#define KOF_CATNAMES_MAX_BYTES (32ull << 20)

enum kof_catnames_flag {
	KOF_CATNAMES_OVER_BUDGET   = 1u,   /* files were left unread for want of room: their ids are spelled in hex */
	KOF_CATNAMES_FILES_REFUSED = 2u,   /* files that do not read as a catalog (the count is in files_refused) */
	KOF_CATNAMES_UNREADABLE    = 4u,   /* a directory could not be read */
	KOF_CATNAMES_NOMEM         = 8u    /* an allocation, or the budget's charge, failed: no names at all from that catalog */
};

struct kof_catnames_info {
	uint32_t flags;
	uint32_t families, variants, tags;
	uint32_t files_refused;
	uint64_t bytes;                    /* what is charged to the budget */
};

/* Build the table from the two directories (either may be NULL: that half is empty). Never returns NULL for a failure of a
 * directory or a file: the answer is a table, possibly empty, with `info` saying why (info may be NULL). NULL only when the table's own
 * struct cannot be allocated or charged (info->flags then has NOMEM). `b` may be NULL (no accounting). */
kof_catnames *kof_catnames_load(const char *pathogens, const char *syndromes, struct kof_budget *b, struct kof_catnames_info *info);
/* Give back what was charged and free. NULL is fine. */
void kof_catnames_free(kof_catnames *n, struct kof_budget *b);
void kof_catnames_info_of(const kof_catnames *n, struct kof_catnames_info *info);

/* WHAT THE DATABASE ITSELF CARRIES (names.kdig: the ids its diagnoses use, id -> name). Asked for an id the catalog directories lack, and for all of them when the host named none:
 * kind 'F' family, 'V' variant (text "Family.A"), 'T' tag; NULL when it has none. The host's catalog answers first, so --bases / keng_catalog_load override and add. */
typedef const char *(*kof_catnames_fallback)(const void *ctx, char kind, uint64_t id);
void kof_catnames_set_fallback(kof_catnames *n, kof_catnames_fallback fn, const void *ctx);

/* The name an id has in the catalog, or NULL (also for 0, for a table that is NULL and for a name that fails its rule). */
const char *kof_catnames_family(const kof_catnames *n, uint64_t id);
const char *kof_catnames_tag(const kof_catnames *n, uint64_t id);

/*
 * The text of an id, always: `n` may be NULL. Returns 1 when the catalog named it, 0 when the text is the hex word. Cut at `cap`.
 *   family  "Mirai"                    else "<8 hex>"
 *   variant "Mirai.A"                  else "<8 hex>"
 *   tag     "Mirai-flood"              else "<8 hex>"
 */
int kof_catnames_family_text(const kof_catnames *n, uint64_t id, char *out, size_t cap);
int kof_catnames_variant_text(const kof_catnames *n, uint64_t id, char *out, size_t cap);
int kof_catnames_tag_text(const kof_catnames *n, uint64_t id, char *out, size_t cap);

/*
 * The family slot of a verdict name. Variant level (variant_id != 0): "Mirai.A"; a variant the catalog does not hold with a family it
 * does: "Mirai.V<8 hex>"; neither: "F<8 hex>.V<8 hex>". Tag level (variant_id == 0): the tag's name, else "T<8 hex>". The slot never
 * holds a separator of the verdict except the one '.' of a variant. `out` needs 96 bytes.
 */
#define KOF_CATNAMES_SLOT_MAX 96u
void kof_catnames_slot(const kof_catnames *n, uint64_t family_id, uint64_t variant_id, uint64_t tag_id, char *out, size_t cap);

#endif /* KOF_CATNAMES_H */
