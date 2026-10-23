/*
 * script_sym.c - a script's symbol block: the names it calls that its language's table gives a meaning.
 *
 * A binary says what it asks of the system by what it imports, and the engine decides from that block whether a diagnose is
 * worth the analysis (the gate). A script has no import table; what it imports is what it calls. The names come from the
 * TEXT route's own reading (kgenome_diag_text_names), so the block and the route cannot disagree about what a script
 * calls, and the viewer's import list for a script is the same thing the gate asked.
 *
 * Imports only (UNDEFINED), each once, as the table spells the name. Which table is the language's own (its profile row in the lib, the one list of
 * what the route serves): a language the route does not serve has no names.
 */

#include "script_sym.h"

#include <phenotype/diag_scan.h>
#include "script_route.h"
#include "script_apply.h"
#include "../binaries/sym_pool.h"

static void put(void *user, const char *name, uint32_t len)
{
	struct kof_symw *w = user;
	struct kof_symrec r = { 0 };

	r.flags = KOF_SYM_F_UNDEFINED;
	r.shndx = 0xffffu;              /* not in a section: it names a function the runtime has */
	r.name = name;
	r.name_len = len;
	(void)kof_symw_put(w, &r);
}

/* The names of a script read from its text: the lib's scan of it, which tells them as the walk meets them. */
struct scan_feed {
	kof_buf  b;
	uint32_t lang;
};

static void feed_scan(void *user, void (*put_fn)(void *, const char *, uint32_t), void *put_user)
{
	const struct scan_feed *f = user;

	kgenome_diag_text_names(f->b.p, f->b.n, f->lang, kof_script_apply, put_fn, put_user);
}

uint32_t kof_script_syms_with(kof_script_names_fn feed, void *feed_user, uint8_t *out, uint32_t cap)
{
	struct kof_symw w;

	if (!out || cap < KOF_SYM_HDRLEN)
		return 0;
	kof_symw_begin(&w, out, cap, 0, 0);
	out[KOF_SYM_H_ORIGIN] = KOF_SYM_ORIGIN_NONE;
	if (feed)
		feed(feed_user, put, &w);
	return kof_symw_end(&w);
}

uint32_t kof_script_syms(kof_buf b, const struct kof_script_info *info, uint8_t *out, uint32_t cap)
{
	struct scan_feed f = { b, info ? kof_script_textual_lang(info->kind) : 0u };

	return kof_script_syms_with(b.p && b.n && f.lang ? feed_scan : NULL, &f, out, cap);
}
