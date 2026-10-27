#define _GNU_SOURCE

/*
 * kv_props.c - the properties page's model: rows, tables, the tab geometry a click
 * is answered from, the event page and prop_build, which picks the rows for the
 * object in hand. The Process page is kv_props_proc.c and the per-format rows are
 * kv_props_obj.c; the types the three share are in kv_props_private.h.
 */

#include "kv_props_private.h"


void prop_add(const char *fmt, ...)
{
	va_list ap;

	if (g_n_prop >= PROP_MAX)
		return;
	va_start(ap, fmt);
	vsnprintf(g_prop[g_n_prop].text, PROP_W, fmt, ap);
	va_end(ap);
	g_n_prop++;
}

/* One sentence of the page in one tone: an empty case, a cut that is reported, a warning. */
void prop_say(const char *attr, const char *fmt, ...)
{
	va_list ap;
	char msg[PROP_W - 32];

	va_start(ap, fmt);
	vsnprintf(msg, sizeof msg, fmt, ap);
	va_end(ap);
	prop_add("%s  %s" A_OFF, attr, msg);
}

/* A heading, with a blank line above it unless it opens the page. */
void prop_head(const char *w)
{
	if (g_n_prop)
		prop_add(A_DIM "%s", "");
	prop_add(A_BOLD "%s" A_OFF, w);
}

/* An offset that may be one of the two sentinels: KGENOME_NA (the format has no such
 * thing - an ET_REL has no entry in the file) or KGENOME_BROKEN (it should, and does
 * not resolve). Printed raw they read as 18446744073709551615. */
void prop_off(char *out, size_t cap, uint64_t v)
{
	if (v == KGENOME_NA)
		snprintf(out, cap, "-");
	else if (v == KGENOME_BROKEN)
		snprintf(out, cap, "unresolved");
	else
		snprintf(out, cap, "0x%llx", (unsigned long long)v);
}

void prop_perm(char *out, size_t cap, unsigned p)
{
	snprintf(out, cap, "%c%c%c", (p & 4) ? 'R' : '-', (p & 2) ? 'W' : '-',
		 (p & 1) ? 'X' : '-');
}

/*
 * THE PROCESS PANEL.
 *
 * Shaped like prop_elf and prop_pe beside it: one function per format, reading
 * that format's info struct off ob->info and writing rows. Nothing here knows
 * where the facts came from - the collector filled a record, the parser turned
 * it into kof_proc_info, and this draws it - which is the same three steps
 * every other panel on this page is made of.
 *
 * THIS IS WHERE THE HEAD AND THE DESCRIPTORS LIVE NOW. They used to be scan
 * REGIONS as well, and they were dropped from that: see KOF_SCAN_PROC_CLAIMED
 * for why a packed struct of integers is not something a signature searches.
 * Not being searchable is not a reason to hide them from a reader, and this is
 * the place a reader looks.
 *
 * The strings are read out of the record's own arena by offset, because the
 * parse already checked those offsets are inside it - `valid` is that check.
 */
const char *prop_proc_str(const struct object *ob, uint32_t off)
{
	const char *p;

	if (!off || off >= ob->buf.n)
		return "";
	p = (const char *)ob->buf.p + off;
	return p;
}
/*
 * The dashboard for one event: where it came from, and what it says.
 *
 * The field rows are the SAME ones the panel shows, from kof_evt_field, for the
 * reason they were made an API in the first place - a page and a panel that
 * described the same record differently would be two vocabularies for one
 * thing. What the page adds is room: every field, untruncated, and the log's
 * own header above them.
 */

/*
 * The dashboard for one event.
 *
 * The rows are composed by kof_inspect_event, which kofexamine uses too - see
 * the note there on why the LAYOUT is shared and not only the wording. What
 * this function decides is the headings and the palette, which are the two
 * things a page has and a printed line does not.
 */
static void prop_event(struct view *v)
{
	static const struct kof_inspect_style style = {
		A_ID, A_LOC, A_WARN, A_OFF
	};
	const struct kofevt_log_hdr *h;

	if (!v->log)
		return;
	h = kofevt_log_header(v->log);

	prop_head("Event log");
	kof_inspect_event_log(h, v->log_events, v->log_n, &style,
			      prop_sink, NULL);

	/*
	 * THE VERB TABLE BELONGS TO THE LOG'S ROW AND NOWHERE ELSE.
	 *
	 * It was on every event's page, where it answered a question about the
	 * whole file that the page was not about. Here it is the point: this
	 * row IS the file, and what a reader wants first is what kind of trace
	 * they have.
	 *
	 * Two columns, with counts. A mask of which verbs are present says a
	 * lot less than how many of each - "RegSet" and "RegSet 41000" are
	 * different facts, and the second is the one that decides where to
	 * look.
	 */
	/*
	 * THE VERB TABLE BELONGS TO THE LOG'S ROW AND NOWHERE ELSE.
	 *
	 * It was on every event's page, where it answered a question about the
	 * whole file that the page was not about. Here it is the point: this
	 * row IS the file, and what a reader wants first is what kind of trace
	 * they have.
	 *
	 * Composed by kof_inspect_event_verbs, so kofexamine says it the same
	 * way - the palette is this tool's, the layout is not.
	 */
	if (v->node[v->sel_node].obj == 0) {
		prop_head("Events by verb");
		kof_inspect_event_verbs(v->log_count, v->log_keep, &style,
					prop_sink, NULL);
		return;
	}

	if (!evt_have_rec(v))
		return;

	/*
	 * "Record", not "This event" - the page is already about one event, so
	 * the heading only has to name what the rows ARE, which is the fields
	 * of its record.
	 */
	prop_head("Record");
	kof_inspect_event(&v->evt, &style, prop_sink, NULL);

	/*
	 * The whole submission's size, which no field row can report: the
	 * record's own says how much of it THIS record holds, and the rest
	 * arrived in continuations.
	 */
	if (v->evt_text_len)
		prop_add("       " A_ID "%-11s" A_OFF A_SIZE "%llu" A_OFF
			 " characters%s", "gathered",
			 (unsigned long long)v->evt_text_len,
			 v->evt_wide ? " (utf-16)" : "");
}

void prop_build(struct view *v)
{
	struct object *ob = cur_obj(v);

	/* A page is built from nothing every frame: no lines, no tables, no pan, a page that scrolls as one. */
	g_n_prop = 0;
	v->prop_n_tab = 0;
	v->prop_hmax = 0;
	v->prop_fixed = v->prop_total = v->prop_vfirst = 0;
	v->sy_fy = -1;
	/* The pages other than the overview are built by kv_props_tab.c, and need none of what the
	 * overview reads (the digest least of all: it reads every byte). */
	if (v->prop_pg != PROP_PG_OVERVIEW) {
		prop_page_table_build(v, ob);
		return;
	}

	/*
	 * THE DIGEST, HERE, BECAUSE THIS IS THE ONLY THING THAT PRINTS IT.
	 *
	 * It reads every byte of the object. Worked out when an object was
	 * merely SELECTED, it faulted a spilled view into memory in full to
	 * fill one row of a pane that may be closed. draw_prop reaches this only when the pane is open, and
	 * the object caches it, so it is still computed once.
	 */
	obj_sha256(ob);
	const char *base = kof_path_sep_last(ob->name);

	base = base ? base + 1 : ob->name;

	/*
	 * THE CHAIN FIRST, THEN THE OBJECT.
	 *
	 * A child on its own is a size and a format with no answer to "where did
	 * this come from" - and that question is most of why anybody opens the
	 * dashboard on a child at all. The enclosing objects are stacked above
	 * it, outermost first, so the panel reads top down the way the engine
	 * reached the bytes: the file, what it held, what that held.
	 *
	 * They are deliberately smaller than the block below them. The object in
	 * focus is what the rest of this page is about; the chain is context,
	 * and context that takes as much room as the subject stops being context.
	 */
	{
		const struct object *up[MAX_OBJ];
		uint32_t n_up = obj_ancestors(v, ob, up, MAX_OBJ), k;

		for (k = 0; k < n_up; k++) {
			char head[32];

			/* k is the depth: 0 is the file, and the count runs the
			 * way the blocks are stacked. */
			snprintf(head, sizeof head, "Enclosing %u", k);
			prop_head(head);
			prop_object_rows(v, up[k], 0);
			/*
			 * THE PROCESS FACTS BELONG TO THE OBJECT THEY ARE
			 * ABOUT, which is the enclosing one - the record.
			 *
			 * Drawn here rather than at the foot of the page: a
			 * reader standing on MEM_HEAP reads down from the
			 * outermost object inwards, and the pid and the
			 * command line are part of what that outermost object
			 * IS. At the bottom they read as an afterthought about
			 * the row in front of them, which is the one thing
			 * they are not.
			 */
			if (up[k]->ctx.format == KOF_EVT_PROC && up[k]->info)
				prop_proc(v, up[k]);
		}
		if (n_up) {
			char head[32];

			/* The chain's last link carries its own number, so the
			 * sequence does not stop one short of the thing it was
			 * counting towards. On a file with nothing above it the
			 * number would be the only one on the page and says
			 * nothing, so it is left off. */
			snprintf(head, sizeof head, "Object %u", n_up);
			prop_head(head);
		} else {
			prop_head("Object");
		}
	}
	prop_object_rows(v, ob, 1);
	/* And when the process record IS the row in front of the reader, the
	 * same panel in the same place - under the object it describes. */
	if (ob->ctx.format == KOF_EVT_PROC && ob->info)
		prop_proc(v, ob);

	/*
	 * AN EVENT'S PAGE IS A DIFFERENT PAGE.
	 *
	 * Everything below - the format block, the regions, the partition check
	 * - is about a parsed file. A record has no parser and no regions, so
	 * that half would be a column of "no parser divides this object" under
	 * a heading that promised otherwise. What a reader wants here is the
	 * log it came from and what the record says.
	 *
	 * NOT for a carried file. A PE that arrived inside a submission is an
	 * executable and gets the ordinary page, headers and regions and all -
	 * see the note in bar_shown about testing the object rather than the
	 * file.
	 */
	/*
	 * A LOG'S OWN ROW GETS THE LOG'S PAGE, not a file's.
	 *
	 * Object 0 is the file - "KOFT-windows-x86_64" - and it was falling
	 * through to the format block, the regions and the partition check,
	 * which described it as raw bytes nobody had parsed. That is true and
	 * it is not what anybody opens a log to read.
	 */
	if (v->log && !v->pe_of[v->node[v->sel_node].obj]) {
		prop_event(v);
		return;
	}

	/*
	 * THE FORMAT BLOCK AND THE FACTS UNDER IT come from kv_dashdata.c as rows (dash_header, dash_regions,
	 * dash_anomalies, dash_heuristic): this function only decides the order they are shown in, and prop_block
	 * draws them. Not for a normalised view: its headers describe the file before the padding came out, so
	 * every offset in them is stale wherever something collapsed ahead of it - dash_header answers an empty block.
	 */
	if (ob->fmt && ob->info && ob->entry_kind != KOF_ENT_NORMALIZED && ob->ctx.format == KOF_FMT_PDF)
		prop_pdf(ob);
	{
		static struct dash_block blk;

		dash_header(ob, &blk);
		prop_block(&blk);
		dash_regions(v, ob, &blk);
		prop_block(&blk);
		dash_anomalies(ob, &blk);
		prop_block(&blk);
	}


	/*
	 * WHO OPENED IT, OR WHAT SAYS SOMETHING SHOULD HAVE.
	 *
	 * Its own section rather than a line under Heuristic, because it is a
	 * different kind of statement: the heuristic scores STRUCTURE and
	 * reports a level, while this says a packer is involved and names the
	 * one thing a reader can do about it. Filing them together put "the
	 * code is hidden" beside "the file is truncated" as though they were
	 * two readings of one measurement.
	 */
	/*
	 * EVERY MODULE THE CHAIN WENT THROUGH, NOT ONLY THE LAST.
	 *
	 * `packer` is one object's own opener or producer, so a payload under
	 * MPRESS, then VMProtect, then a string decryptor said the last of them
	 * and nothing of the two that had to come off first. The enclosing
	 * objects are the same list the chain above is drawn from (obj_ancestors),
	 * outermost first; a name is dropped when the line before it said it
	 * already, because the file's "opened by" and its child's "unpacked by"
	 * are the two ends of one edge (see the note at prop_object_rows).
	 */
	const struct object *up[MAX_OBJ];
	const char *step[MAX_OBJ + 1u];
	uint32_t n_up = obj_ancestors(v, ob, up, MAX_OBJ), n_step = 0, ks;

	for (ks = 0; ks <= n_up; ks++) {
		const char *name = ks < n_up ? up[ks]->packer : ob->packer;

		if (name[0] && !(n_step && strcmp(step[n_step - 1u], name) == 0))
			step[n_step++] = name;
	}
	if (n_step || emu_why_tag(ob->emu_why)) {
		prop_head("Packer");
		for (ks = 0; ks < n_step; ks++) {
			char lab[16];

			if (n_step > 1u)
				snprintf(lab, sizeof lab, "module %u", ks + 1u);
			else
				snprintf(lab, sizeof lab, "module");
			prop_add("  %-11s " A_BAD "%s" A_OFF, lab, step[ks]);
		}
		if (!n_step)
			prop_add("  %-11s %s%s" A_OFF A_DIM "  %s" A_OFF,
				 "verdict",
				 ob->emu_why == KGENOME_EMU_UNP_WHY_DENSE
				 ? A_BAD : A_WARN,
				 emu_why_tag(ob->emu_why),
				 emu_why_reason(ob->emu_why));
		if (!n_step)
			prop_add(A_DIM "  %-11s Analysis > Examine with "
				 "emulator" A_OFF, "try");
	}

	{
		static struct dash_block blk;

		dash_heuristic(ob, &blk);
		prop_block(&blk);
	}
}
