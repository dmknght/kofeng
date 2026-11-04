/* kv_chooser_take.inc - the taking half of each chooser kind; included by kv_chooser.c (see kv_chooser_open.inc). */

/*
 * TAKING A ROW: one function per kind, found by `what`.
 *
 * ch_take was one function of 653 lines, a chain of `if (c->what == CH_...)`.
 * Each kind is a static function that reads v->ch (the row is c->sel, already
 * closed by ch_take) and acts. The kinds that act on one matcher of the draft
 * (the marker, the threshold, the anchor, the rule, the range) first take the
 * matcher `arg` names through ch_take_group, which is the check the old chain
 * made after its last branch. The opening half is kv_chooser_open.inc.
 */

/*
 * THE ATTRIBUTE FORM'S ROWS, BY NAME.
 *
 * Fixed, because every row is always offered: unlike the range list, nothing
 * here is ever declined, so the index IS the row and there is no verb to
 * carry. The two rules and the Apply row are part of the numbering - a list
 * that renumbered when a separator moved would be the same drift chooser.verb
 * exists to prevent.
 */
enum {
	CH_ATTR_ICASE = 0,
	CH_ATTR_SEP1,
	CH_ATTR_TOKEN,
	CH_ATTR_FULLWORD,
	CH_ATTR_PATTERN,
	CH_ATTR_SEP2,
	CH_ATTR_APPLY,
	CH_ATTR_ROWS
};

/* AN ANCHOR'S VALUE and the sentinel it may have instead: see AT_NO_ANCHOR. */

/*
 * WHAT AN ANCHOR IS WORTH IN THIS OBJECT, or that it is worth nothing.
 *
 * bof is zero by definition, eof is the object's size, and entry is whatever
 * the parser resolved - which may be nothing at all, KGENOME_NA for a format with
 * no such notion and KGENOME_BROKEN when it could not be worked out. Converting a
 * place between anchors is arithmetic on these, so the absent case has to be
 * an answer rather than a number: AT_NO_ANCHOR is returned and the caller
 * refuses the move.
 */
#define AT_NO_ANCHOR INT64_MIN

/* Does this format define every region bit in the mask - see the note below on
 * why "no" and "called something else" are different answers. The symbol halves
 * belong to no format and are always known; see rng_name_of. */
static int rgn_bits_known(const struct kof_parser *p, uint32_t mask)
{
	uint32_t b, k;

	mask &= ~(uint32_t)KOF_SCAN_SYM;
	for (b = 0; b < 30u; b++) {
		int found = 0;

		if (!(mask & (1u << b)))
			continue;
		if (p)
			for (k = 0; k < p->n_regions; k++)
				found |= p->regions[k] == (1u << b);
		if (!found)
			return 0;
	}
	return 1;
}

static void at_warn_if_multi(struct view *v)
{
	uint32_t m = v->ed.dr.fmt_mask, g;
	int n_fmt = 0;

	for (; m; m >>= 1)
		n_fmt += (int)(m & 1u);
	if (n_fmt < 2)
		return;

	/*
	 * DO THE REGIONS STILL MEAN THE SAME THING - the louder of the two.
	 *
	 * The region axis is ONE bit space shared by every format, and that is
	 * what makes a signature over PE and ELF work at all: bit 1 is HEADERS
	 * in both, bit 2 CODE, bit 3 DATA, each format resolving it to its own
	 * extents. A rule about a cross-platform build is written once against
	 * those bits and is right in both.
	 *
	 * The correspondence STOPS AFTER BIT 3, and it stops silently. Bit 5 is
	 * UNCLAIMED in an ELF and OVERLAY in a PE; bit 4 is NOLOAD, SIGNATURE,
	 * PACKED or CONTENT depending on who is asked. Such a matcher does not
	 * fail to fire - it searches a DIFFERENT REAL REGION, which is the one
	 * answer worth interrupting for. So the names are compared rather than
	 * the bits, because the name is the thing the author meant.
	 */
	for (g = 0; g < v->ed.dr.n_grp; g++) {
		char first[64] = "", other[64];
		uint32_t want = grp_mask(&v->ed, g);
		uint8_t ff = 0, f;

		if (!grp_has_range(&v->ed, g) || (want & KOF_SCAN_ALL))
			continue;
		for (f = 0; f < KOF_FMT_COUNT; f++) {
			if (!(v->ed.dr.fmt_mask & (1u << f)))
				continue;
			/*
			 * ABSENT IS NOT THE SAME AS NAMED DIFFERENTLY, and
			 * rng_name_of cannot tell them apart: a bit the format
			 * does not define is skipped, and a mask that named
			 * nothing falls out of it as "WHOLE-FILE". Reported
			 * from that string alone this would have said a
			 * matcher searches the whole file where it in fact
			 * searches NOTHING - kof_scan_resolve_range returns no
			 * extents - which is the opposite mistake.
			 */
			if (!rgn_bits_known(kof_parser_of(f), want)) {
				say_err(&v->ed,
					"matcher %u searches nothing in %s - "
					"that format has no such region",
					grp_loc(&v->ed, g), kof_format_name(f));
				return;
			}
			rng_name_of(kof_parser_of(f), want, other,
				    sizeof other);
			if (!first[0]) {
				snprintf(first, sizeof first, "%s", other);
				ff = f;
				continue;
			}
			if (strcmp(first, other)) {
				say_err(&v->ed,
					"matcher %u: that region is %s in %s "
					"and %s in %s", grp_loc(&v->ed, g),
					first,
					kof_format_name(ff), other,
					kof_format_name(f));
				return;
			}
		}
	}

	for (g = 0; g < v->ed.dr.n_grp; g++)
		if (grp_is_at(v->ed.dr.grp[g].rule)) {
			say_note(&v->ed,
				 "find_at is one offset - it means a "
				 "different place in each of %d formats",
				 n_fmt);
			return;
		}
}


/* What picking the highlighted item does. */
/*
 * WHICH RULE A ROW OF THE KIND MENU MEANS.
 *
 * The menu used to be the rule list itself - row 0 was find_all, row 1
 * find_any, row 2 find_multi - so the row index WAS the value and two places
 * wrote `q->rule = c->sel`. The three searches are one row now, and the number
 * chooses between them afterwards, so the two are no longer the same thing and
 * the mapping is stated once.
 *
 * A new find_str starts as "every one of them": it is the strictest reading,
 * it is what a matcher with one marker in it means either way, and it FOLLOWS
 * the markers - adding another tightens the rule rather than leaving a number
 * behind. See grp_thresh_eff, which answers `count` for it.
 */
static int ch_rule_of_row(int row)
{
	return row == 1 ? 3 : 0;        /* find_at, else find_str */
}

static int64_t at_anchor_val(uint8_t anchor, uint64_t entry, uint64_t size)
{
	if (anchor == KOF_ANCHOR_ENTRY)
		return (entry == KGENOME_NA || entry == KGENOME_BROKEN)
		     ? AT_NO_ANCHOR : (int64_t)entry;
	if (anchor == KOF_ANCHOR_EOF)
		return (int64_t)size;
	return 0;                       /* bof */
}

/* The matcher a row of the list is about, or NULL when `arg` names none. */
static struct group *ch_take_group(struct view *v)
{
	return v->ch.arg < v->ed.dr.n_grp ? &v->ed.dr.grp[v->ch.arg] : NULL;
}

static void ch_take_hfam(struct view *v)
{
	struct chooser *c = &v->ch;

	decl_pick_family(v, (uint32_t)c->sel);
	return;
}

static void ch_take_hvar(struct view *v)
{
	struct chooser *c = &v->ch;

	decl_pick_variant(v, c->verb[c->sel]);
	return;
}

static void ch_take_utype_utag(struct view *v)
{
	struct chooser *c = &v->ch;

	uint32_t i = c->arg & 0xffffu;
	uint8_t *ut = NULL;
	char *tag = NULL;

	if (c->arg & CH_UNIT_GRP) {
		if (i < v->ed.dr.n_grp) {
			ut = &v->ed.dr.grp[i].utype;
			tag = v->ed.dr.grp[i].tag;
		}
	} else if (i < v->ed.dr.n_cnd) {
		ut = &v->ed.dr.cnd[i].utype;
		tag = v->ed.dr.cnd[i].tag;
	}
	if (!ut)
		return;
	if (c->what == CH_UTYPE) {
		*ut = (uint8_t)(c->verb[c->sel] + 1u);
	} else if (c->verb[c->sel] && v->tag &&
		   (uint32_t)c->verb[c->sel] - 1u < v->tag->cat.n) {
		snprintf(tag, KOF_NAME_MAX + 1, "%s", v->tag->cat.tag[c->verb[c->sel] - 1u].name);
	} else {
		tag[0] = 0;
	}
	return;
}

static void ch_take_fmt_cat(struct view *v)
{
	struct chooser *c = &v->ch;

	/* The nth kind that still has something to offer - the same
	 * walk that built the list. Picking one opens its formats
	 * beside it, the way every other two-level menu here does. */
	uint32_t ci, n = 0;
	struct chooser up = *c;

	for (ci = 0; ci <= FMT_CAT_N; ci++) {
		if (!ch_fmt_cat_langs(ci) &&
		    !(ch_fmt_cat_mask(ci) & ~v->ed.dr.fmt_mask))
			continue;
		if ((int)n == c->sel) {
			up.open = 1;
			ch_open_beside(v, ch_fmt_cat_langs(ci) ? CH_FMT_LANG
						     : CH_FMT_ADD, ci, &up);
			v->ch_up = up;
			return;
		}
		n++;
	}
	return;
}

static void ch_take_fmt_lang(struct view *v)
{
	struct chooser *c = &v->ch;

	/*
	 * The format and the language in one act - see the note where
	 * the list is built.
	 */
	if (c->sel >= 0 && (uint32_t)c->sel < script_sub_n) {
		v->ed.dr.fmt_mask |= 1u << KOF_FMT_SCRIPT;
		if (c->sel == 0) {
			v->ed.dr.opt_on[OPT_SUBTYPE] = 0;
			v->ed.dr.opt_val[OPT_SUBTYPE] = 0;
		} else {
			v->ed.dr.opt_on[OPT_SUBTYPE] = 1;
			v->ed.dr.opt_val[OPT_SUBTYPE] =
				(uint32_t)c->sel;
		}
		/* Same reason as the format taker below: adding one
		 * can make the target set ambiguous for an offset. */
		at_warn_if_multi(v);
	}
	return;
}

static void ch_take_fmt(struct view *v)
{
	struct chooser *c = &v->ch;

	/*
	 * The nth kind the list offered, walked again rather than
	 * remembered so the two cannot disagree - and past them, the
	 * Remove row.
	 */
	uint32_t ci, n = 0;
	struct chooser up = *c;

	for (ci = 0; ci <= FMT_CAT_N; ci++) {
		if (!ch_fmt_cat_langs(ci) &&
		    !(ch_fmt_cat_mask(ci) & ~v->ed.dr.fmt_mask))
			continue;
		if ((int)n == c->sel) {
			up.open = 1;
			ch_open_beside(v, ch_fmt_cat_langs(ci) ? CH_FMT_SW_LANG
						     : CH_FMT_SW,
				FMT_SW_PACK(ci, c->arg), &up);
			v->ch_up = up;
			return;
		}
		n++;
	}
	/*
	 * Past every kind is the Remove row, and it is TESTED for
	 * rather than fallen into: a row added after it some day would
	 * otherwise quietly start removing the format instead.
	 */
	if (c->sel == c->n - 1) {
		uint64_t fm = v->ed.dr.fmt_mask;

		if (fm && !(fm & (fm - 1u)))
			say_note(&v->ed, "A rule needs at least one format");
		else
			ch_fmt_swap(v, c->arg, KOF_FMT_COUNT);
	}
	return;
}

static void ch_take_fmt_sw(struct view *v)
{
	struct chooser *c = &v->ch;

	uint8_t f, n = 0, pick = KOF_FMT_COUNT;
	uint32_t pool = ch_fmt_cat_mask(FMT_SW_CAT(c->arg)) &
			~v->ed.dr.fmt_mask;

	for (f = 0; f < KOF_FMT_COUNT; f++)
		if (pool & (1u << f)) {
			if ((int)n == c->sel)
				pick = f;
			n++;
		}
	if (pick < KOF_FMT_COUNT)
		ch_fmt_swap(v, FMT_SW_WHICH(c->arg), pick);
	return;
}

static void ch_take_fmt_sw_lang(struct view *v)
{
	struct chooser *c = &v->ch;

	/*
	 * A SCRIPT AND ITS LANGUAGE, in place of whatever was clicked.
	 * The same walk the list was built with, minus the language
	 * already in use - see ch_fmt_lang_skip.
	 */
	uint32_t k, n = 0, skip = ch_fmt_lang_skip(v), pick = script_sub_n;

	for (k = 0; k < script_sub_n; k++) {
		if (k == skip)
			continue;
		if ((int)n == c->sel) {
			pick = k;
			break;
		}
		n++;
	}
	if (pick >= script_sub_n)
		return;
	ch_fmt_swap(v, FMT_SW_WHICH(c->arg), KOF_FMT_SCRIPT);
	if (pick == 0) {
		v->ed.dr.opt_on[OPT_SUBTYPE] = 0;
		v->ed.dr.opt_val[OPT_SUBTYPE] = 0;
	} else {
		v->ed.dr.opt_on[OPT_SUBTYPE] = 1;
		v->ed.dr.opt_val[OPT_SUBTYPE] = pick;
	}
	return;
}

static void ch_take_fmt_add(struct view *v)
{
	struct chooser *c = &v->ch;

	uint8_t f, n = 0, pick = KOF_FMT_COUNT;
	uint32_t pool = ch_fmt_cat_mask(c->arg) & ~v->ed.dr.fmt_mask;

	/* The nth format the list offered, walked again rather than
	 * remembered so the two cannot disagree. */
	for (f = 0; f < KOF_FMT_COUNT; f++)
		if (pool & (1u << f)) {
			if ((int)n == c->sel)
				pick = f;
			n++;
		}
	if (pick < KOF_FMT_COUNT)
		v->ed.dr.fmt_mask |= 1u << pick;
	/* Only here: a SWITCH leaves the count alone, and the count is
	 * what makes an offset ambiguous. */
	at_warn_if_multi(v);
	return;
}

static void ch_take_enc_type(struct view *v)
{
	struct chooser *c = &v->ch;

	if (c->sel >= 0 && c->sel < KOF_CODEC_COUNT)
		v->enc_type = (uint32_t)c->sel;
	/* The result belonged to the coding that produced it. */
	v->enc_res_n = 0;
	v->enc_done = 0;
	/*
	 * AND THE CARET GOES WHERE THE READER WILL TYPE NEXT.
	 *
	 * Picking from the chooser goes through the general click path,
	 * which clears the focus on the way past - "any click leaves
	 * whatever was being typed". So after choosing a coding there
	 * was no field with the caret at all, and the next Tab moved to
	 * the input rather than to the key: choosing caesar and typing
	 * the shift put the shift into the encoded text.
	 *
	 * A coding with a key wants the key next; one without wants the
	 * text. Saying so here is also the answer to "what did picking
	 * this actually do", which a blank caret does not give.
	 */
	if (kof_codec_keyed(v->enc_type)) {
		v->edit = ED_ENC_KEY;
		v->caret = (uint32_t)strlen(v->enc_key);
	} else {
		v->edit = ED_ENC_IN;
		v->caret = (uint32_t)strlen(v->enc_in);
	}
	return;
}

static void ch_take_arch(struct view *v)
{
	struct chooser *c = &v->ch;

	v->ed.dr.opt_val[OPT_ARCH] = arch_word[(size_t)c->sel % ARCH_N].val;
	return;
}

static void ch_take_subtype(struct view *v)
{
	struct chooser *c = &v->ch;

	v->ed.dr.opt_val[OPT_SUBTYPE] = (uint32_t)c->sel;
	return;
}

static void ch_take_opt(struct view *v)
{
	struct chooser *c = &v->ch;

	struct object *ob = cur_obj(v);
	int seen = 0, k;

	for (k = 0; k < OPT_COUNT; k++) {
		/*
		 * THE SAME QUESTION THE LIST ASKED - see ch_opt_offerable.
		 *
		 * These skips used to be written out again here, and the
		 * two spellings disagreed on the commonest object there
		 * is: the list offers "File subtype" when the format has
		 * a NAME for the object's subtype, and KGENOME_PE_EXE is
		 * zero with the name "EXE", while this loop skipped any
		 * subtype that was zero. So on an ordinary PE the row
		 * was offered, picked, and silently did nothing.
		 */
		if (!ch_opt_offerable(v, k))
			continue;
		if (seen++ != c->sel)
			continue;
		v->ed.dr.opt_on[k] = 1;
		/* Chosen from the menu, so it is the draft's from
		 * here on - see kof_draft.opt_auto. */
		v->ed.dr.opt_auto[k] = 0;
		v->ed.dr.opt_val[k] = k == OPT_SIZE_MIN ? ob->buf.n :
				k == OPT_SIZE_MAX ? ob->buf.n * 2u :
				k == OPT_ARCH ? ob->ctx.arch
					      : ob->ctx.subtype;
		break;
	}
	return;
}

static void ch_take_declkind(struct view *v)
{
	struct chooser *c = &v->ch;

	struct decl *d;

	if (!decl_reserve(&v->ed, v->ed.dr.n_decl + 1u))
		return;
	/*
	 * NOT WIRED YET, AND SAID RATHER THAN DONE QUIETLY - see
	 * DECL_RX. The row is offered because it is the menu this panel
	 * is meant to have; what is behind it is written later.
	 */
	if (c->sel == 2) {
		say_note(&v->ed, "Regex is not wired yet");
		return;
	}
	/*
	 * `at` is KGENOME_BROKEN - the bytes are not in this object and may
	 * never be. That is a state struct decl already has, for a
	 * marker carried from another sample, and the table draws it as
	 * "not here" rather than as an error.
	 */
	d = &v->ed.dr.decl[v->ed.dr.n_decl];
	memset(d, 0, sizeof *d);
	d->obj = v->ed.cur;
	d->at = KGENOME_BROKEN;
	d->fullword = KOF_WORD_SUBSTRING;
	d->hex = c->sel == 1 ? DECL_HEX : DECL_STR;
	snprintf(d->rgn, sizeof d->rgn, "-");
	v->ed.dr.sel_decl = v->ed.dr.n_decl;
	v->ed.dr.n_decl++;
	decl_edit_open(v, v->ed.dr.n_decl - 1u);
	return;
}

static void ch_take_attr(struct view *v)
{
	struct chooser *c = &v->ch;

	struct decl *d = c->arg < v->ed.dr.n_decl
		       ? &v->ed.dr.decl[c->arg] : NULL;

	if (!d)
		return;
	if (c->sel == CH_ATTR_APPLY) {
		/* The one row that writes, and the list is already
		 * closed - ch_take shut it on the way in. */
		d->icase = c->pend_icase;
		d->fullword = c->pend_word;
		decl_locate(&v->ed, d);   /* the hit list depends on both */
		return;
	}
	switch (c->sel) {
	case CH_ATTR_ICASE:    c->pend_icase = !c->pend_icase; break;
	case CH_ATTR_TOKEN:    c->pend_word = KOF_WORD_TOKEN; break;
	case CH_ATTR_FULLWORD: c->pend_word = KOF_WORD_FULLWORD; break;
	case CH_ATTR_PATTERN:  c->pend_word = KOF_WORD_SUBSTRING; break;
	default:               return;   /* a rule, or nothing */
	}
	/*
	 * STILL OPEN, and on the row that was just pressed.
	 *
	 * The cell holds two independent facts, so one visit has to be
	 * able to set both - a list that closed on the first press
	 * would let a visit change half the cell, which is what the
	 * two separate columns already did. ch_take closed it at the
	 * top; this is the row saying it is not finished.
	 */
	ch_attr_items(c);
	c->open = 1;
	return;
}

static void ch_take_range2(struct view *v)
{
	struct chooser *c = &v->ch;

	/*
	 * One range is the subject, and c->arg2 holds its mask - put
	 * there when the menu was built, so the taker cannot disagree
	 * with the row about which range was pressed even if the draft
	 * changed shape in between.
	 */
	uint32_t cur = c->arg2, rest = ch_rng_regions(v) & ~cur;
	int verb = (c->sel >= 0 && c->sel < c->n)
		 ? (int)c->verb[c->sel] : 2;
	uint32_t b, rb = 0;

	for (b = 0; b < 32u; b++)
		rb += (rest >> b) & 1u;

	if (verb == 0) {                /* extend */
		if (rb == 1u) {
			rng_retarget(&v->ed, cur, cur | rest);
			say_note(&v->ed, "%s", "Scan range extended");
		} else if (rb > 1u) {
			struct chooser up = *c;

			up.open = 1;
			ch_open_beside(v, CH_RANGE_EXT, cur, &up);
			v->ch_up = up;
		}
		return;
	}
	if (verb == 1) {                /* drop one region */
		struct chooser up = *c;

		up.open = 1;
		ch_open_beside(v, CH_RANGE_DROP, cur, &up);
		v->ch_up = up;
		return;
	}
	/* verb 2: remove the whole range, matcher and all. */
	{
		uint32_t dm[2u * MAX_GROUP];
		int du[2u * MAX_GROUP];
		uint32_t dn = rng_removable(&v->ed, dm, du, 2u * MAX_GROUP), i;

		for (i = 0; i < dn; i++)
			if (dm[i] == cur) {
				rng_delete(&v->ed, cur, du[i]);
				return;
			}
		/* Not in the removable list means a matcher searches it
		 * and rng_delete's own walk will take that matcher; ask
		 * it directly rather than refusing. */
		rng_delete(&v->ed, cur, 0);
	}
	return;
}

static void ch_take_range_add(struct view *v)
{
	struct chooser *c = &v->ch;

	uint32_t have = ch_rng_regions(v), b, n = 0, pick = 0;

	for (b = 0; b < 32u; b++) {
		if (!(have & (1u << b)))
			continue;
		if ((int)n++ == c->sel) {
			pick = 1u << b;
			break;
		}
	}
	/* Past the last region is the WHOLE-FILE row. */
	rng_apply(&v->ed, 2, 0, pick ? pick : KOF_SCAN_ALL);
	return;
}

static void ch_take_range_pick(struct view *v)
{
	struct chooser *c = &v->ch;

	uint32_t cur = c->arg;          /* the same field the build read */
	uint32_t set = c->what == CH_RANGE_EXT
		     ? (ch_rng_regions(v) & ~cur) : cur;
	uint32_t b, n = 0, pick = 0;

	for (b = 0; b < 32u; b++) {
		if (!(set & (1u << b)))
			continue;
		if ((int)n++ == c->sel) {
			pick = 1u << b;
			break;
		}
	}
	if (!pick)
		return;
	if (c->what == CH_RANGE_EXT) {
		rng_retarget(&v->ed, cur, cur | pick);
		say_note(&v->ed, "%s", "Scan range extended");
	} else {
		/*
		 * Narrowed, not removed: the range keeps every region
		 * but this one. Taking the LAST region away would leave
		 * a matcher searching nothing, which is what Remove is
		 * for - so it is refused here rather than silently
		 * producing one.
		 */
		if ((cur & ~pick) == 0) {
			say_err(&v->ed, "%s", "That is the range's only "
				"region - remove the range instead");
			return;
		}
		rng_retarget(&v->ed, cur, cur & ~pick);
		say_note(&v->ed, "%s", "Region dropped from the scan range");
	}
	return;
}

static void ch_take_cmatch(struct view *v)
{
	struct chooser *c = &v->ch;

	struct cond *cc;
	uint32_t i, n = 0;

	if (c->arg >= v->ed.dr.n_cnd)
		return;
	cc = &v->ed.dr.cnd[c->arg];
	for (i = 0; i < v->ed.dr.n_grp; i++) {
		size_t l;

		if (!cmatch_ok(v, c->arg, i))
			continue;
		if ((int)n++ != c->sel)
			continue;
		/*
		 * Appended with & rather than replacing the text: the
		 * expression is the author's, and a second matcher
		 * usually narrows a condition. Anything else - an |, a
		 * parenthesis - is still typed into the box, which is
		 * why the box stays.
		 */
		l = strlen(cc->expr);
		snprintf(cc->expr + l, sizeof cc->expr - l, "%s%u",
			 l ? (cc->op ? "|" : "&") : "",
			 grp_loc(&v->ed, i));
		break;
	}
	return;
}

static void ch_take_cmatch2(struct view *v)
{
	struct chooser *c = &v->ch;

	uint32_t ci = CH_PAIR_C(c->arg), m = CH_PAIR_M(c->arg);
	/*
	 * The verb is carried on the row, not read off c->sel: "Switch"
	 * is offered only while there is somewhere to switch to, so a
	 * fixed row number would carry out Remove whenever it was not.
	 */
	int verb = (c->sel >= 0 && c->sel < c->n)
		 ? (int)c->verb[c->sel] : 2;

	if (ci >= v->ed.dr.n_cnd || m >= v->ed.dr.n_grp)
		return;
	if (verb == 0) {
		cnd_negate_matcher(&v->ed, &v->ed.dr.cnd[ci], m);
		return;
	}
	if (verb == 1) {
		struct chooser up = *c;

		up.open = 1;
		ch_open_beside(v, CH_CSWAP, c->arg, &up);
		v->ch_up = up;
		return;
	}
	cnd_drop_matcher(&v->ed, &v->ed.dr.cnd[ci], m);
	return;
}

static void ch_take_cswap(struct view *v)
{
	struct chooser *c = &v->ch;

	uint32_t ci = CH_PAIR_C(c->arg), m = CH_PAIR_M(c->arg);
	uint32_t i, n = 0;

	if (ci >= v->ed.dr.n_cnd || m >= v->ed.dr.n_grp)
		return;
	/* The same walk the list was built from, so row N names the
	 * matcher printed on row N even if the draft changed shape
	 * while the menu was open. */
	for (i = 0; i < v->ed.dr.n_grp; i++) {
		if (!cmatch_ok(v, ci, i))
			continue;
		if ((int)n++ != c->sel)
			continue;
		cnd_swap_matcher(&v->ed, ci, m, i);
		break;
	}
	return;
}

static void ch_take_rule(struct view *v)
{
	struct chooser *c = &v->ch;
	struct group *q;

	if (c->arg == MAX_GROUP) {
		/* A new condition: the rule is chosen before there is anything
		 * in it, which is the order somebody thinks in. */
		if (v->ed.dr.n_grp >= MAX_GROUP) {
			say_err(&v->ed, "No room for another matcher");
			return;
		}
		grp_add(&v->ed);
		if (!v->ed.dr.n_grp)
			return;
		q = &v->ed.dr.grp[v->ed.dr.n_grp - 1u];
		/* Through ch_rule_of_row rather than writing c->sel into
		 * `rule`: this used to do that, and the row number is not the
		 * rule. */
		q->rule = ch_rule_of_row(c->sel);
		/* Nothing in it yet, so there is no marker to seed from - the
		 * offset arrives with the first one. See grp_seed_at. */
		return;
	}
	q = ch_take_group(v);
	if (!q)
		return;
	q->rule = ch_rule_of_row(c->sel);
	/* Chosen now, from whatever marker the matcher already holds -
	 * see grp_seed_at. Switching away and back does not lose it,
	 * because it is only ever written here and by the offset menu. */
	if (grp_is_at(c->sel)) {
		grp_seed_at(&v->ed, c->arg);
		at_warn_if_multi(v);
	}
}

static void ch_take_marker(struct view *v)
{
	struct chooser *c = &v->ch;

	if (!ch_take_group(v))
		return;
	uint32_t i, n = 0;

	for (i = 0; i < v->ed.dr.n_decl; i++) {
		if (v->ed.dr.decl[i].grp & (1u << c->arg))
			continue;
		if (!rng_holds(grp_mask(&v->ed, c->arg), v->ed.dr.decl[i].mask))
			continue;
		if ((int)n++ != c->sel)
			continue;
		v->ed.dr.decl[i].grp |= 1u << c->arg;
		/* An AT matcher built rule-first has no offset until it
		 * has a marker; this is when it gets one. */
		if (grp_is_at(v->ed.dr.grp[c->arg].rule))
			grp_seed_at(&v->ed, c->arg);
		break;
	}
}

static void ch_take_thresh(struct view *v)
{
	struct chooser *c = &v->ch;
	struct group *q = ch_take_group(v);

	if (!q)
		return;
	/* The list starts at 1 - see CH_THRESH where it is built. */
	uint32_t want = (uint32_t)c->sel + 1u;
	uint32_t n = grp_count(&v->ed, c->arg);

	/*
	 * THE NUMBER CHOOSES THE CALL BACK.
	 *
	 * This is the whole of the merge: one row in the kind menu, and
	 * the threshold decides which of the three the generator writes
	 * - so a rule still comes out as kof_find_str_all, _any or
	 * _multi, an old rule still reads back unchanged, and the
	 * short-circuit && and || give is kept exactly where it applies.
	 *
	 * `all` is a SENTINEL and not the number n: it follows the
	 * markers, so adding one keeps the rule meaning all of them.
	 */
	/*
	 * ONE MARKER IS "any", NOT "all", AND THE ORDER SAYS SO.
	 *
	 * With one marker the two calls test the same thing, so the
	 * choice is about what the generated source READS as -
	 * `kof_find_str_all(rng, s0)` is a plural about a single thing.
	 * The threshold menu offers exactly one row in that case, so
	 * nothing is being taken away from the author either: there is
	 * no second answer for this test to be overriding.
	 *
	 * It costs the sentinel in that one case. `all` follows the
	 * markers - adding one keeps the rule meaning all of them -
	 * and a group that went from one marker to two now reads ">=
	 * 1" instead of "all 2". That is the right way round: the
	 * author who adds a second marker is deciding something, and
	 * the panel shows them what the rule currently says rather
	 * than changing it under them.
	 */
	if (want <= 1u)
		q->rule = 1;            /* >= 1  -> find_any */
	else if (n && want >= n)
		q->rule = 0;            /* == n  -> find_all */
	else {
		q->rule = 2;            /* >= N  -> find_multi */
		q->thresh = want;
	}
}

static void ch_take_atoff(struct view *v)
{
	struct chooser *c = &v->ch;
	struct group *q = ch_take_group(v);

	if (!q)
		return;
	/*
	 * ONE ROW PER ANCHOR, so the row IS the anchor - see where
	 * the list is built. It used to walk the occurrence rows
	 * first to work out how many of them there were, which is
	 * what a list answering two questions costs its reader.
	 */
	uint64_t entry = cur_obj(v) ? cur_obj(v)->ctx.entry_off
				    : KGENOME_NA;
	uint64_t size = cur_obj(v) ? cur_obj(v)->ctx.obj_size : 0;
	int64_t base_old, base_new;

	if (c->sel < 0 || c->sel >= KOF_ANCHOR_COUNT)
		return;
	base_old = at_anchor_val(q->at_anchor, entry, size);
	base_new = at_anchor_val((uint8_t)c->sel, entry, size);
	/*
	 * AN ANCHOR THIS OBJECT DOES NOT HAVE CANNOT EXPRESS THE
	 * PLACE, so the move is refused rather than carried out
	 * against a sentinel. ctx->entry_off is KGENOME_NA for a format
	 * with no entry point and KGENOME_BROKEN when it could not be
	 * resolved.
	 */
	if (base_old == AT_NO_ANCHOR || base_new == AT_NO_ANCHOR) {
		say_note(&v->ed,
			 "This object has no %s to count from",
			 kof_anchor_word(c->sel));
		return;
	}
	/*
	 * THE PLACE IS PRESERVED AND THE STEP FOLLOWS IT - but only
	 * for a step the ENGINE put there. A number somebody typed is
	 * a step from the anchor it was typed against, and converting
	 * it would overrule what they wrote. See group.at_auto.
	 */
	if (q->at_auto)
		q->at_off = base_old + q->at_off - base_new;
	q->at_anchor = (uint8_t)c->sel;
	/* And the sign belongs to the new anchor - see
	 * grp_at_fix_sign. A no-op on the converted path; the
	 * correction that matters on the other one. */
	grp_at_fix_sign(q);
}

static void ch_take_range(struct view *v)
{
	struct chooser *c = &v->ch;
	struct group *q = ch_take_group(v);

	if (!q)
		return;
	/*
	 * The same list the menu was built from, walked in the same
	 * order - see the note there. Past the last defined range is
	 * the WHOLE-FILE row.
	 */
	uint32_t rm[2 * MAX_GROUP];
	int ru[2 * MAX_GROUP];
	uint32_t nr = rng_all(&v->ed, rm, ru, 2u * MAX_GROUP);

	q->mask = (c->sel >= 0 && (uint32_t)c->sel < nr)
		? rm[c->sel] : KOF_SCAN_ALL;
	/* Choosing the region is the other moment the correspondence
	 * can break - see at_warn_if_multi. */
	at_warn_if_multi(v);
}
