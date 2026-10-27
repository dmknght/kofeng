/*
 * kx_dash_stubs.h - what the rest of the viewer would answer, for the two dashboard tests (kx_dash, kx_dashdata): the row
 * writer, the half of the symbol block a mask names (an oracle written from the record flags, not from kof_sym_extents),
 * the offset spelling, the field editor and the regex compile. Included once by each test, after kv.h and hk.h.
 */
#ifndef KX_DASH_STUBS_H
#define KX_DASH_STUBS_H

/* ---- the stubs: what the rest of the viewer would answer ------------------------------------------------- */

struct prop_line g_prop[PROP_MAX];
uint32_t         g_n_prop;
int g_mx, g_my;
int g_mod_shift, g_mod_ctrl;

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

void prop_say(const char *attr, const char *fmt, ...)
{
	va_list ap;
	char msg[PROP_W - 32];

	va_start(ap, fmt);
	vsnprintf(msg, sizeof msg, fmt, ap);
	va_end(ap);
	prop_add("%s  %s" A_OFF, attr, msg);
}

void prop_head(const char *w)
{
	if (g_n_prop)
		prop_add(A_DIM "%s", "");
	prop_add(A_BOLD "%s" A_OFF, w);
}

void prop_perm(char *out, size_t cap, unsigned p)
{
	snprintf(out, cap, "%c%c%c", (p & 4) ? 'R' : '-', (p & 2) ? 'W' : '-', (p & 1) ? 'X' : '-');
}

/* The half a mask names: imports are the records flagged undefined, exports the rest - an oracle of the engine's extents,
 * written from the record flags and not from kof_sym_extents. */
uint32_t sym_row_mask(uint8_t which)
{
	return which == SYMN_IMP ? KOF_SCAN_SYM_IMP : KOF_SCAN_SYM_EXP;
}

uint32_t sym_half_recs(const struct object *o, uint32_t mask, struct kof_range *ext, uint32_t cap, uint32_t *idx,
		       uint32_t idx_cap)
{
	uint32_t n = kof_sym_count(o->sym, (uint32_t)o->sym_n), i, k = 0;

	(void)ext; (void)cap;
	for (i = 0; i < n && k < idx_cap; i++) {
		const uint8_t *r = kof_sym_rec(o->sym, (uint32_t)o->sym_n, i);
		int imp;

		if (!r)
			continue;
		imp = (r[KOF_SYM_R_FLAGS] & KOF_SYM_F_UNDEFINED) != 0;

		if ((mask & KOF_SCAN_SYM_IMP) ? imp : !imp)
			idx[k++] = i;
	}
	return k;
}

uint32_t sym_half(const struct object *o, uint32_t mask, struct kof_range *ext, uint32_t cap, uint64_t *bytes)
{
	static uint32_t tmp[KOF_SYM_MAX_RECS];

	if (bytes)
		*bytes = 0;
	return sym_half_recs(o, mask, ext, cap, tmp, KOF_SYM_MAX_RECS);
}

void sym_flag_str(uint8_t f, char *out)
{
	snprintf(out, 8, "f%02x", f);
}

void sym_shn_str(const uint8_t *r, char *out, size_t n)
{
	snprintf(out, n, (r[KOF_SYM_R_FLAGS] & KOF_SYM_F_UNDEFINED) ? "UND" : "%u", (unsigned)kof_sym_u16(r, KOF_SYM_R_SHNDX));
}

int rx_compile(const char *text, uint8_t *prog, uint32_t cap, uint32_t *n_out, char *err, size_t err_n)
{
	uint32_t n;

	*n_out = 0;
	if (err && err_n)
		err[0] = 0;
	if (!text || !text[0])
		return 0;
	n = kof_regex_compile(text, prog, cap, 0);
	if (!n) {
		if (err && err_n)
			snprintf(err, err_n, "%s", "bad pattern");
		return 0;
	}
	*n_out = n;
	return 1;
}

static int g_field_keys HK_UNUSED;
int field_key(struct view *v, char *buf, size_t cap, int k, int (*accept)(int))
{
	size_t n = strlen(buf);

	(void)accept;
	g_field_keys++;
	if ((k == 127 || k == 8) && n)
		buf[n - 1] = 0;
	else if (k >= 0x20 && k < 0x7f && n + 1 < cap) {
		buf[n] = (char)k;
		buf[n + 1] = 0;
	}
	(void)v;
	return 1;
}

void field_draw(struct out *o, const char *text, uint32_t caret, uint32_t *off, int room, int editing, const char *ph)
{
	(void)o; (void)text; (void)caret; (void)off; (void)room; (void)editing; (void)ph;
}


void prop_off(char *out, size_t cap, uint64_t v)
{
	if (v == KGENOME_NA)
		snprintf(out, cap, "-");
	else if (v == KGENOME_BROKEN)
		snprintf(out, cap, "unresolved");
	else
		snprintf(out, cap, "0x%llx", (unsigned long long)v);
}


int heur_of(const struct object *ob, struct kof_heur_facts *out, int32_t *score, const char **guess)
{
	memset(out, 0, sizeof *out);
	out->format = ob->ctx.format;
	out->anomalies = ob->heur.heur_anomalies;
	out->flags = ob->heur.heur_flags;
	*score = ob->heur.heur_score;
	*guess = "Unknown";
	return ob->heur.heur_scored != 0;
}


#endif
