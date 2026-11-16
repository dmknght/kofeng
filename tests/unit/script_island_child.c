/*
 * script_island_child - an island (the lineage-resolved argument of an eval()/create_function()
 * call reached only through a variable and a join, diag_text_walk.c's layer_of_call) is a REAL
 * CHILD OBJECT of the engine's own tree, reached through the public scan API exactly like any
 * other child (a container's entry, an unpacked image, a script's own normalised view) - not a
 * scanner-free side computation only a viewer could see, which is the shape this task replaces
 * (Merge 168's kof_script_island_units adapter and kofexaminer_blocks.c's now-removed island row).
 *
 * RED on the code before this task: scanning HOHO below through the PUBLIC API (kscan_bytes, the
 * same path any host uses) never hands the callback an object whose bytes are the resolved body
 * and whose kind is KOF_ENT_SCRIPT - the value existed only inside one C call of the lineage walk
 * (freed before this task, Merge 168) or, after Merge 168, only as a line kofexaminer printed by
 * calling the lib a second time itself; no (off, len) of the object TREE ever pointed at it, so no
 * object of the tree ever carried it. GREEN after: such a child is there, carries the SAME
 * declared-language facts the normalised view already gets (st_facts's "the producer's language
 * beats the one read back") and can be told apart as a genuine child by its name (KOF_OBJ_SEP).
 *
 * WHY THE OLD TESTS MISSED THIS: there is no "old test" to miss - this is new coverage of a new
 * mechanism (the island becoming a pipeline child), not a regression of existing behaviour; the
 * RED/GREEN pair above is the project's own substitute for a brand new mechanism.
 *
 * UPDATED (owner, 2026-11-10, second correction): "không treat cái island này như 1 object riêng
 * để scan" and "script norm phải là 0 và cái island... là cái 1, 2, 3". RED on the code before
 * THIS change (Merge 169): the island carried `res->has_verdict` (it was scored as an independent
 * object, `//0:island@0x...`, ahead of the normalised view's `//1`) - this file's own original
 * assertions said so (`island_found == 1` by entry_kind alone, with no ordering or verdict
 * check). GREEN after: the island still arrives as a real, tokenized/normalised KOF_ENT_SCRIPT
 * child (unchanged from the first RED/GREEN pair above), but AFTER the normalised view in
 * declaration order and with NO verdict of its own.
 *
 * Fixture: tests/lib/genome/diag_text_islands.c's own HOHO constant (hoho.php's real shape,
 * trimmed to what the evaluator needs) - reused rather than re-derived: that file already proves
 * the LIBRARY resolves it to one island of exactly `function x($t,$k){return $t^$k;}` (33 bytes);
 * this proves the ENGINE turns what it resolves into a real, listed object.
 */

#include <stdio.h>
#include <string.h>

#include "../../libkofeng/kofeng.h"
#include "../../libkofeng/kofcore/kofmod/kofsig.h"
#include "../../libkofeng/kofcore/kofmod/script.h"

static int failures;

#define CK(c, ...) do { if (!(c)) { printf("  FAIL %s:%d  ", __FILE__, __LINE__); printf(__VA_ARGS__); printf("\n"); failures++; } } while (0)

/* hoho.php's exact shape, trimmed (tests/lib/genome/diag_text_islands.c's HOHO, copied rather than
 * shared across a tests/lib and a tests/unit binary, which link differently - see kofeng/CLAUDE.md
 * "Where code lives" on the two test trees). */
#define HOHO \
	"<?php\n" \
	"$l=str_replace('k','','ckrekatek_fuknkkction');" \
	"$a='function x($t,$k){return ';" \
	"$b='$t^$k;}';" \
	"$U=$a.$b;" \
	"$s=$l('',$U);"

static const char ISLAND_BODY[] = "function x($t,$k){return $t^$k;}";

/*
 * ISL-1 (owner, 2026-11-10, "fix luôn đi chứ"): the island's OWN further view - a flat chain of
 * statements the resolved payload never broke onto more than one line, exactly hoho.php's real
 * shape (STATUS.md's Merge 172) - never arrived: ctx->format stayed KOF_FMT_UNKNOWN the moment the
 * island became the scanner's own current object (sx_identify has no "<?php" to read a tagless
 * fragment's format from), so sx_script_forms refused it outright; fixed by declaring the
 * island's own image description too (oc_child_desc, objctx_script.c) and telling the form pass
 * the island's body is a tagless FRAGMENT (oc_script_form_req.fragment) the same way the
 * function-finder already does, so php's own tag/island lexer reads it as code rather than as
 * markup with nothing in it to reformat.
 */
#define HOHO2 \
	"<?php\n" \
	"$l=str_replace('k','','ckrekatek_fuknkkction');" \
	"$a='$aa=11;$bb=22;$cc=33;';" \
	"$b='$dd=44;$ee=55;';" \
	"$U=$a.$b;" \
	"$s=$l('',$U);"

static const char ISLAND2_BODY[] = "$aa=11;$bb=22;$cc=33;$dd=44;$ee=55;";

struct seen2 {
	int      objects;
	int      island_found;
	int      grandchild_found;
	char     grandchild_bytes[128];
	uint64_t grandchild_len;
};

static int on_object2(const char *name, const void *bytes, uint64_t len,
		      const struct kof_result *res, void *user)
{
	struct seen2 *s = user;

	(void)name;
	s->objects++;
	if (bytes && len == sizeof ISLAND2_BODY - 1u &&
	    memcmp(bytes, ISLAND2_BODY, (size_t)len) == 0 &&
	    res->entry_kind == KOF_ENT_SCRIPT) {
		s->island_found++;
		return 0;
	}
	/*
	 * The root's own normalised view is KOF_ENT_NORMALIZED too and arrives first (slot 0), but
	 * its bytes are the obfuscated source ("$l=str_replace(...)"), never "$aa=" - told apart by
	 * content, the only thing an on_object callback is given.
	 */
	if (res->entry_kind == KOF_ENT_NORMALIZED && bytes && len >= 3 &&
	    !memcmp(bytes, "$aa", 3) && len < sizeof s->grandchild_bytes) {
		s->grandchild_found++;
		s->grandchild_len = len;
		memcpy(s->grandchild_bytes, bytes, (size_t)len);
		s->grandchild_bytes[len] = 0;
	}
	return 0;
}

struct seen {
	int      objects;
	int      island_found;
	int      island_order;         /* s->objects at the moment the island arrived */
	int      island_has_verdict;
	uint8_t  island_subtype;
	uint8_t  island_lang_known;
	char     island_name[160];
	int      view_found;
	int      view_order;           /* s->objects at the moment the normalised view arrived */
};

static int on_object(const char *name, const void *bytes, uint64_t len,
		     const struct kof_result *res, void *user)
{
	struct seen *s = user;

	s->objects++;
	if (bytes && len == sizeof ISLAND_BODY - 1u &&
	    memcmp(bytes, ISLAND_BODY, (size_t)len) == 0 &&
	    res->entry_kind == KOF_ENT_SCRIPT) {
		s->island_found++;
		s->island_order = s->objects;
		s->island_has_verdict = res->has_verdict;
		s->island_subtype = res->subtype;
		s->island_lang_known = res->lang_known;
		snprintf(s->island_name, sizeof s->island_name, "%s", name ? name : "");
	} else if (res->entry_kind == KOF_ENT_NORMALIZED) {
		s->view_found++;
		s->view_order = s->objects;
	}
	return 0;
}

int main(void)
{
	static const char *db = "build/release/databases";
	struct kof_engine *eng;
	struct kof_scanner *sc;
	struct kof_scan_option opt;
	struct seen s;
	int rc;

	eng = keng_open(db);
	if (!eng) {
		printf("script island child: no database at %s - nothing tested\n", db);
		return 0;
	}
	sc = kscan_new(eng);
	if (!sc) {
		keng_close(eng);
		printf("script island child: could not make a scanner\n");
		return 1;
	}

	memset(&opt, 0, sizeof opt);
	/* deep: the same heur_level >= 2 gate sx_script_forms already reads (scan_forms.c) - without
	 * it neither the normalised view nor an island is ever asked for, by design (the cost is the
	 * fold's own walk, see objctx_script.c's header). */
	opt.heur_level = KOF_HEUR_LEVEL_MAX;
	memset(&s, 0, sizeof s);
	rc = kscan_bytes(sc, HOHO, strlen(HOHO), "hoho_min.php", &opt, on_object, &s);

	if (rc <= 0)
		CK(0, "the file was not scanned at all (rc=%d)", rc);
	CK(s.island_found == 1,
	   "expected exactly one child whose bytes are the resolved island body and whose kind is "
	   "KOF_ENT_SCRIPT, got %d (of %d object(s) scanned)", s.island_found, s.objects);
	if (s.island_found == 1) {
		CK(s.island_subtype == KOF_SCRIPT_PHP,
		   "island child's declared subtype is %u, wanted KOF_SCRIPT_PHP (%u) - the SAME "
		   "declared-language mechanism the normalised view already uses (script_declare)",
		   (unsigned)s.island_subtype, (unsigned)KOF_SCRIPT_PHP);
		CK(s.island_lang_known,
		   "island child does not carry lang_known, though script_declare sets it for every "
		   "child it declares");
		CK(strstr(s.island_name, KOF_OBJ_SEP) != NULL,
		   "island child's own name ('%s') has no " KOF_OBJ_SEP " child separator - this is "
		   "not a real child of the object tree", s.island_name);
		CK(!s.island_has_verdict,
		   "island child has its own verdict (has_verdict=1) - it must not be an "
		   "independent scan target, only evidence (owner, 2026-11-10)");
		CK(strstr(s.island_name, "island@0x") == NULL,
		   "island child's name ('%s') still uses the old island@0x<hex> label - it must "
		   "name the variable, the line and the language instead (owner, 2026-11-10)",
		   s.island_name);
		CK(strstr(s.island_name, "$") != NULL,
		   "island child's name ('%s') drops the PHP '$' sigil off the variable name "
		   "(owner, 2026-11-10, fourth correction)", s.island_name);
		CK(strstr(s.island_name, "PHP") == NULL,
		   "island child's name ('%s') repeats the language word a second time - "
		   "obj_label (kv_tree_label.c) already composes \"Script-PHP\" from "
		   "entry_kind/subtype for every script object, the island included, so the "
		   "label must not carry it too (owner, 2026-11-10; kofeng/CLAUDE.md #2)",
		   s.island_name);
		CK(s.view_found == 1,
		   "expected exactly one normalised view (entry_kind KOF_ENT_NORMALIZED) beside "
		   "the island, got %d", s.view_found);
		if (s.view_found == 1)
			CK(s.view_order < s.island_order,
			   "the normalised view must be declared BEFORE the island (slot 0, island "
			   "1/2/3...) - view arrived as object #%d, island as #%d",
			   s.view_order, s.island_order);
	}

	/* ISL-1: a flat, unbroken chain in the island's OWN body gets its own further view, same
	 * as hoho.php's real payload (STATUS.md's Merge 172/ISL-1). */
	{
		struct seen2 s2;

		memset(&s2, 0, sizeof s2);
		rc = kscan_bytes(sc, HOHO2, strlen(HOHO2), "hoho2_min.php", &opt, on_object2, &s2);
		if (rc <= 0)
			CK(0, "HOHO2 was not scanned at all (rc=%d)", rc);
		CK(s2.island_found == 1,
		   "expected exactly one island child matching the flat chain's resolved body, got %d "
		   "(of %d object(s) scanned)", s2.island_found, s2.objects);
		CK(s2.grandchild_found == 1,
		   "the island's own further view (ISL-1) did not arrive: expected one more "
		   "KOF_ENT_NORMALIZED child starting \"$aa=\", got %d", s2.grandchild_found);
		if (s2.grandchild_found == 1)
			CK(strstr(s2.grandchild_bytes, "$aa=11;\n$bb=22;") != NULL &&
			   strstr(s2.grandchild_bytes, "$cc=33;\n$dd=44;") != NULL,
			   "the island's own further view is not reflowed one statement per line: %s",
			   s2.grandchild_bytes);
	}

	kscan_free(sc);
	keng_close(eng);

	if (failures) {
		printf("script island child: %d failure(s)\n", failures);
		return 1;
	}
	printf("script island child: ok\n");
	return 0;
}
