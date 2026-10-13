#define _GNU_SOURCE
#include "kv.h"


/*
 * What the gate found, as a name and as a reason.
 *
 * The NAME is the whole of what the status line says. A sentence explaining
 * which measurement fired was tried there and was simply too long - it pushed
 * everything else off the row, and "Unknown packer" already tells a reader both
 * that something packed this and that nothing here knows what. The reason
 * belongs on the dashboard, where there is a line for it.
 *
 * Two wordings for two strengths of claim: dense executable segments select
 * nothing across 1 246 clean binaries, so that one is a statement; a header
 * that cannot be loaded is weaker, because every instance of it in the malware
 * corpus turned out to be a truncated file rather than a packed one.
 */


const char *emu_why_tag(uint8_t why)
{
	return why == KGENOME_EMU_UNP_WHY_DENSE  ? "Unknown packer"
	     : why == KGENOME_EMU_UNP_WHY_BROKEN ? "Possible packer"
	     : why == KGENOME_EMU_UNP_WHY_LOADER ? "Possible encryptor" : NULL;
}

const char *emu_why_reason(uint8_t why)
{
	return why == KGENOME_EMU_UNP_WHY_DENSE
	       ? "executable segments too dense to be code"
	     : why == KGENOME_EMU_UNP_WHY_LOADER
	       ? "an encrypted block sits in a non-code segment"
	       : "header cannot be loaded as written";
}

void draw_marker_line(struct out *o, struct view *v)
{
	struct object *ob = cur_obj(v);
	/* Wide enough for the action slot, which is the longest thing that lands
	 * here: a dump reports counts, a byte total and a directory name. */
	char name[80], right[200];
	/* The right hand text is not always a readout: while the draft has the
	 * focus it can be a complaint, and a complaint in the colour of a
	 * readout is one people scroll past. */
	const char *rcol = NULL;
	uint32_t hit = 0, i;

	/* The rule that closes the draft panel, and so the one that separates
	 * the status line from whatever is above it. Drawn here rather than in
	 * draw_decl because it is the status line's border as much as the
	 * panel's, and it has to be there when there is no panel too. */
	if (g_decl_rows) {
		int c2;

		row_start(o, mark_row() - 1, 1);
		out_str(o, A_DIM);
		for (c2 = 0; c2 < g_cols; c2++)
			out_str(o, "-");
		out_str(o, A_OFF);
	}

	row_start(o, mark_row(), 1);

	/*
	 * Which module opened this object, and which version of the format it
	 * found - the left hand end, where it has been, because it is a property
	 * of the object rather than of what is being done to it.
	 *
	 * The version earns its place beside the name: "UPX.ELF" says a packer
	 * was recognised, and the version is what decides whether the layout the
	 * module walked is the one this file actually uses. When they disagree
	 * the recovered bytes are short and nothing else on the screen says why.
	 */
	/*
	 * The colour separates two things this field has always conflated.
	 *
	 * A PACKER stays red. Nothing legitimate ships an executable wrapped in
	 * UPX or Ezuri without a reason, and the wrapper is there to stop the
	 * file being read - which is a fact about intent, and belongs in the
	 * colour the rest of the screen reserves for what is wrong.
	 *
	 * A DECOMPRESSOR OR PARSER goes yellow. "This came out of a zip", "this
	 * came out of an RTF" says only how the object was reached. Archives and
	 * documents are how software is shipped; red there made every object
	 * inside a container look like a finding before a module had run.
	 *
	 * The version stays beside the name and stays dim - it qualifies the
	 * name rather than competing with it, and it is the field that decides
	 * which layout the rest of what the module said belongs to.
	 */
	if (ob->packer[0]) {
		/*
		 * Which sort of unpacker, from the ENGINE - it knows, because
		 * every unpack module declares it. The name table this used to
		 * consult was a guess that would misclassify the twelfth module.
		 *
		 * TWO FIELDS, because the name beside an object means two
		 * different things depending on which object it is. On the file
		 * itself it is the module that OPENED it, and PACKED says
		 * whether that module was a packer. On a child it is the module
		 * that PRODUCED it, and from_packer says the same thing about
		 * that. Either one being true means the name here is a packer's.
		 */
		const char *pcol =
			(ob->heur.from_packer ||
			 (ob->heur.heur_flags &
			  KOF_HEUR_FL(KOF_HEUR_F_PACKED))) ? A_BAD : A_WARN;

		/* One field - see where it is filled. */
		out_fmt(o, "%s%s" A_OFF, pcol, ob->packer);
		out_str(o, A_DIM "  |  " A_OFF);
	} else if (!emu_why_tag(obj_emu_why(ob))) {
		/*
		 * NO MODULE OPENED IT, so the object is named by what the engine
		 * says it is - "Norm" for a normalised view, the language of a
		 * script, the format otherwise. Crafted by kof_object_label from
		 * the object's own state; nothing is worked out here.
		 */
		char label[48];

		kof_object_label(ob->entry_kind, NULL, ob->ctx.format,
				 ob->ctx.subtype, label, sizeof label);
		out_fmt(o, "%s%s" A_OFF, ob->entry_kind == KOF_ENT_NORMALIZED
					? A_ID : "", label);
		out_str(o, A_DIM "  |  " A_OFF);
	} else if (emu_why_tag(obj_emu_why(ob))) {
		/*
		 * NO MODULE NAMED IT, AND IT STILL LOOKS PACKED.
		 *
		 * The same slot, because it answers the same question - what
		 * got this object into the shape it is in - and a reader who
		 * has learnt to look here for "UPX.ELF v13" should find the
		 * next best answer in the same place rather than nowhere.
		 */
		out_fmt(o, "%s%s" A_OFF,
			obj_emu_why(ob) == KGENOME_EMU_UNP_WHY_DENSE ? A_BAD
								: A_WARN,
			emu_why_tag(obj_emu_why(ob)));
		out_str(o, A_DIM "  |  " A_OFF);
	}

	if (!ob->n_touch) {
		int32_t hsc = 0;
		const char *hguess = "Unknown";

		/*
		 * NO MARKER IS NOT THE SAME AS NOTHING TO SAY.
		 *
		 * "no markers" was the whole of this line for an object no
		 * signature knows, and on an object the heuristic would report
		 * that reads as an all clear - the one reading it must never
		 * have. A scan of the same file prints a finding; this said the
		 * database is quiet, which is true and beside the point.
		 *
		 * Spelled the way the scanner spells it, because it is the same
		 * verdict and a reader should be able to match the two by eye
		 * rather than by working out that they are about one thing.
		 */
		/*
		 * The packer tag wins the line when both apply.
		 *
		 * They are not competing readings of the same evidence - one
		 * says something hid this object's code, the other that its
		 * structure is wrong - but the status line holds one and the
		 * packer is the one worth acting on: it names a button to
		 * press. The heuristic verdict is not lost, it is on the
		 * dashboard a keystroke away, on its own line.
		 */
		if (emu_why_tag(ob->emu_why))
			out_str(o, A_DIM "no markers" A_OFF);
		else if (heur_reports(ob, &hsc, &hguess))
			out_fmt(o, A_HEUR "Heur:%s#s%d" A_OFF A_DIM
				"  no marker" A_OFF, hguess, hsc);
		else
			out_str(o, A_DIM "no markers" A_OFF);
	} else {
		char hits[24], skips[24];
		int c;

		for (i = 0; i < ob->n_touch; i++)
			hit += (uint32_t)(ob->touch[i].fired != 0);
		/*
		 * "No rule selected" is a real state - it is what an object
		 * that matched nothing starts in, so that the hex pane does not
		 * light up wherever some unselected rule's marker happened to
		 * land. The counts still mean something there; the name does
		 * not, and reading it would be reading one past the array.
		 */
		if (v->sel_touch < ob->n_touch) {
			kof_touch_name(&ob->touch[v->sel_touch], name, sizeof name);
		} else {
			snprintf(name, sizeof name, "no marker selected");
		}

		/*
		 * Capitalised, because they are the labels of two controls
		 * rather than words in a sentence - the same way every other
		 * button on this screen is written.
		 *
		 * "Matched" and "Skipped" rather than "Hit" and "Skip". The
		 * dashboard has said "matched" and "skipped" for as long as it
		 * has existed, and the two screens describing one fact in two
		 * vocabularies is a thing a reader has to translate. They also
		 * say what happened to the OBJECT: "Hit" is jargon for what
		 * happened to the module.
		 */
		snprintf(hits, sizeof hits, "Matched %u", hit);
		snprintf(skips, sizeof skips, "Skipped %u", ob->n_touch - hit);

		/*
		 * <Object> | <Verdict name> | <verdict info>: the name of the
		 * selected rule first, then how many matched and were skipped.
		 * They were the other way round, with the name last and followed
		 * by a count of the rule's markers - which the dashboard and the
		 * markers list already say, and which crowded the line.
		 */
		c = 1 + (int)o->col_hint;
		v->name_c0 = c;
		v->name_c1 = c + (int)strlen(name) - 1;
		c += (int)strlen(name) + 5;
		v->hit_c0 = c;
		v->hit_c1 = c + (int)strlen(hits) - 1;
		c += (int)strlen(hits) + 2;
		v->skip_c0 = c;
		v->skip_c1 = c + (int)strlen(skips) - 1;

		out_fmt(o, "%s%s" A_OFF A_DIM "  |  " A_OFF,
			v->sel_touch < ob->n_touch
			? touch_colour(&ob->touch[v->sel_touch]) : A_DIM,
			name);
		out_fmt(o, "%s%s" A_OFF A_DIM "  %s" A_OFF,
			hit ? A_BAD : A_DIM, hits, skips);
	}

	/*
	 * The right half.
	 *
	 * A selection is reported as its size and its two offsets, and not as
	 * its contents: the contents are on the screen a few rows up, in colour,
	 * and repeating twenty of them here says nothing the highlight has not.
	 *
	 * Both offsets, because a signature is written against one and a bug
	 * report is written against the other, and which is which is exactly the
	 * thing that gets confused.
	 */
	/*
	 * The draft's own commentary, while the draft is what is being worked
	 * on.
	 *
	 * Only then: it is about a panel, and shown while the hex pane has the
	 * focus it would be answering a question nobody asked, in the space the
	 * selection needs. Same order of urgency it had beside the button -
	 * what is wrong, then what is missing, then what would be a duplicate,
	 * then where this draft lives.
	 */
	if (v->find_msg[0]) {
		snprintf(right, sizeof right, "%s", v->find_msg);
		rcol = A_WARN;
		goto have_right;
	}
	/*
	 * What the last copy did, wherever it was made from.
	 *
	 * Its own slot rather than the panel's commentary below, because that
	 * one only shows while the draft panel has focus and a copy is almost
	 * always made from the hex pane. Put there, the one message that exists
	 * to stop a silent failure was itself silent.
	 */
	/*
	 * AND IT FADES.
	 *
	 * This slot had no expiry at all: it was written when something
	 * happened and cleared only by opening the dashboard. So "opened a3"
	 * from a file switch sat on the status line for the rest of the
	 * session, outranking the selection readout - the reader drags out a
	 * run of bytes, the line still says what happened a minute ago, and the
	 * one number they asked for by dragging never appears.
	 *
	 * A confirmation is worth a few seconds. A FAILURE is worth longer:
	 * it is the message somebody has to act on, and it competes with a
	 * selection they can make again in a second.
	 */
	if (v->act_msg[0]) {
		static char last[sizeof v->act_msg];
		static uint64_t since;
		uint64_t now = now_ms();

		if (strcmp(last, v->act_msg) != 0) {
			snprintf(last, sizeof last, "%s", v->act_msg);
			since = now;
		}
		if (now - since > (v->act_ok ? 4000u : 15000u))
			v->act_msg[0] = 0;
	}
	if (v->act_msg[0]) {
		snprintf(right, sizeof right, "%s", v->act_msg);
		rcol = v->act_ok ? A_SIZE : A_WARN;
		goto have_right;
	}
	/*
	 * A word about the marker list, while the marker list is what is open.
	 *
	 * The panel's commentary below is scoped to the panel having focus,
	 * which is right for it and wrong here: this dialog is over the panel
	 * and the reader is not in it, so a note about the row they just
	 * clicked had nowhere to appear at all.
	 */
	if (v->show_list && v->list_depth && v->ed.dr.warn[0]) {
		snprintf(right, sizeof right, "%s", v->ed.dr.warn);
		rcol = v->ed.dr.warn_bad ? A_BAD : A_WARN;
		goto have_right;
	}
	if (v->pane == 3 && g_decl_rows) {
		/* Nothing is wrong with a draft nobody has begun - see
		 * draft_started. The reasons appear with the first thing the
		 * author puts in it, which is when they mean anything. */
		const char *why = draft_started(&v->ed) ? draft_missing(&v->ed)
							: NULL;
		int near_miss = 0;
		const char *dup = why ? NULL : draft_dup(&v->ed, &near_miss);

		if (v->ed.dr.warn[0]) {
			snprintf(right, sizeof right, "%s", v->ed.dr.warn);
			rcol = v->ed.dr.warn_bad ? A_BAD : A_WARN;
		} else if (why) {
			/* Something required is absent, which is why the
			 * button is greyed - an error, and coloured as one. */
			snprintf(right, sizeof right, "%s", why);
			rcol = A_BAD;
		} else if (dup) {
			/* Both readings are the same kind of thing: a rule in
			 * the tree worth looking at before writing another.
			 * Neither is a failure, and the exact-match one is the
			 * reading that follows a Save As that worked. */
			snprintf(right, sizeof right, "%s %s",
				 near_miss ? "all but one marker of"
					   : "same markers as", dup);
			rcol = A_WARN;
		}
		else if (v->ed.dr.gen_path[0])
			snprintf(right, sizeof right, "%.*s%s",
				 (int)sizeof right - 12, v->ed.dr.gen_path,
				 draft_dirty(&v->ed) ? "  (unsaved)" : "");
		else
			right[0] = 0;
		if (right[0])
			goto have_right;
	}
	if (v->sel_a != KGENOME_BROKEN) {
		uint64_t lo = v->sel_a < v->sel_b ? v->sel_a : v->sel_b;
		uint64_t hi = v->sel_a < v->sel_b ? v->sel_b : v->sel_a;

		/* One offset in front and the other in brackets after it: they
		 * are the same place said twice, not two columns to line up. */
		/* And which hit it is, when the selection is one: after a
		 * search the useful question is not only where this match is
		 * but how many there are and how far through them you are. */
		/* The wording an editor uses. "hit 1/1" reads as a ratio of
		 * something, and the thing it was a ratio of was never said. */
		/*
		 * THE SAME PAIR, BUT THE FIRST NUMBER IS NOT A FILE OFFSET.
		 *
		 * A symbol row resolves to extents like any other row, so both
		 * halves of the pair are real here: view_map gives the position
		 * in the BLOCK and `lo` the position in the row. Only the word
		 * changes, because the block is built and calling that number a
		 * file offset is what led to a marker declared here being
		 * looked for in the file.
		 */
		if (sym_view(v))
			snprintf(right, sizeof right,
				 "%llu B   block 0x%08llx (row: 0x%08llx)",
				 (unsigned long long)(hi - lo + 1u),
				 (unsigned long long)view_map(v, lo, 0),
				 (unsigned long long)lo);
		/*
		 * A LINE AND A COLUMN, for something a person reads.
		 *
		 * The byte offset of a character in a php file is not a fact
		 * anybody uses: what a reader wants when they point at
		 * something in a script is where it is in the source, which is
		 * what every editor and every error message they have ever seen
		 * says. The byte offset is still what the selection IS - see
		 * the note on rgn_at - and it is still shown, second, because
		 * it is what a marker is taken at.
		 */
		else if (text_pane(v)) {
			struct object *tob = cur_obj(v);
			uint64_t tn = tob ? tob->buf.n : 0;
			const uint8_t *tb = tob ? tob->buf.p : NULL;
			uint64_t ls, line;

			if (!tb)
				tn = 0;
			ls = txt_line_start(v, tb, tn, lo);
			line = txt_line_of(v, tb, tn, ls) + 1u;
			snprintf(right, sizeof right,
				 "%llu B   line %llu col %llu   "
				 "(offset 0x%08llx)",
				 (unsigned long long)(hi - lo + 1u),
				 (unsigned long long)line,
				 (unsigned long long)(lo - ls + 1u),
				 (unsigned long long)view_map(v, lo, 0));
		} else if (v->find_n && v->find_i)
			snprintf(right, sizeof right,
				 "match %u of %u   %llu B   offset 0x%08llx "
				 "(region: 0x%08llx)",
				 v->find_i, v->find_n,
				 (unsigned long long)(hi - lo + 1u),
				 (unsigned long long)view_map(v, lo, 0),
				 (unsigned long long)lo);
		else
			snprintf(right, sizeof right,
				 "%llu B   offset 0x%08llx (region: 0x%08llx)",
				 (unsigned long long)(hi - lo + 1u),
				 (unsigned long long)view_map(v, lo, 0),
				 (unsigned long long)lo);
	} else if (ob->broken) {
		/*
		 * The engine did not finish this object, said here because
		 * nothing else on the screen would say it.
		 *
		 * It is on the RIGHT and it is LAST. Right, because it is a
		 * fault and the left hand end is where the object describes
		 * itself; last, because it is a standing condition rather than
		 * a reply - it is true for as long as the object is open, and a
		 * selection or a search the reader just made is the thing they
		 * are waiting on. It comes back the moment they let go.
		 *
		 * Why it matters on this screen in particular: an unpack that
		 * stopped part way still yields an object, and that object
		 * looks entirely ordinary. A signature written against the
		 * CODE of half a recovered image is a signature written against
		 * a coincidence.
		 */
		snprintf(right, sizeof right, "not finished: %s",
			 kverdict_broken_name(ob->broken));
		rcol = A_BAD;
	} else {
		right[0] = 0;
	}

have_right:
	if (right[0]) {
		int at, room = g_cols - (int)o->col_hint - 4;

		/*
		 * CUT TO FIT, NOT DROPPED FOR NOT FITTING.
		 *
		 * The test used to be "does the whole of it fit", and a message
		 * that did not was simply not drawn - so the longest messages,
		 * which are the ones that explain something, were the ones
		 * nobody ever saw. The hex compiler's refusals are three lines
		 * of advice and vanished entirely; the reader was left with a
		 * marker of length zero and no reason for it.
		 */
		if (room > 8 && (int)strlen(right) > room) {
			right[room - 3] = '.';
			right[room - 2] = '.';
			right[room - 1] = '.';
			right[room] = 0;
		}
		at = g_cols - (int)strlen(right) - 1;

		if (at > (int)o->col_hint + 2) {
			out_at(o, mark_row(), at);
			out_fmt(o, "%s%s" A_OFF,
				rcol ? rcol :
				v->sel_a != KGENOME_BROKEN ? "\033[44;97m" : A_DIM,
				right);
		}
	}
}
