/*
 * orbit/evt - the event record and the file it is kept in.
 *
 *   evt_record   640 bytes of anything, read as a struct kof_evt: rendered, counted, labelled, listed field by field with
 *                the extent of each, joined as content, read as wide text. The record sits at the END of a page whose
 *                successor is PROT_NONE, so a read past it is a fault. The arena's last byte is forced to NUL (what the log
 *                reader guarantees and the channel does not: unit test orbit_evt, row WP12-10), because without it every
 *                random record would only find that one defect again.
 *   cmdline_norm kof_cmdline_norm over bytes and a random capacity, against the three properties it states.
 *   evtlog       a log file of anything (a memfd named through /proc/self/fd): open, header, count, every record read, seeks
 *                and extents; the reader's own promises (the arena ends in NUL, count covers what a read finds, a read
 *                never needs more than rec_size) are the invariants. Seeds are logs the library's own writer made.
 */
#include "orbit_fx.h"

#include "kofevtfmt.h"
#include "kofevtlog.h"

/* ------------------------------------------------------------------------------------------------- evt_record */

static void mk(struct kof_evt *e, uint16_t verb)
{
	memset(e, 0, sizeof *e);
	e->verb = verb;
	e->pid = 321;
	e->actor_pid = 321;
	e->ppid = 12;
	e->tid = 654;
	e->stamp = 132000000000000000ull;
	e->seq = 7;
	e->os = KOF_OS_LINUX;
	e->off_image = e->off_object = e->off_cmdline = e->off_data = KOF_TEXT_NONE;
}

static struct fz_field fld[24];
static struct fz_map map_evt;

static void field(uint32_t off, unsigned size, enum fz_fkind kind)
{
	struct fz_field *f = &fld[map_evt.n++];

	f->off = off;
	f->size = (uint8_t)size;
	f->be = 0;
	f->kind = (uint8_t)kind;
}

static void seeds_evt(struct fz_corpus *c)
{
	unsigned v;

	map_evt.f = fld;
	map_evt.n = 0;
#define AT(m) (uint32_t)offsetof(struct kof_evt, m)
	field(AT(verb), 2, FZ_COUNT);
	field(AT(off_image), 2, FZ_OFFSET);
	field(AT(off_object), 2, FZ_OFFSET);
	field(AT(off_cmdline), 2, FZ_OFFSET);
	field(AT(text_len), 2, FZ_LEN);
	field(AT(content_len), 2, FZ_LEN);
	field(AT(off_data), 2, FZ_OFFSET);
	field(AT(data_len), 2, FZ_LEN);
	field(AT(source), 1, FZ_COUNT);
	field(AT(loc), 1, FZ_COUNT);
	field(AT(attack), 2, FZ_COUNT);
	field(AT(u), 8, FZ_LEN);
	field(AT(u) + 8u, 8, FZ_LEN);
#undef AT
	for (v = 1; v < KOF_EVT_TYPE_COUNT; v++) {
		struct kof_evt e;

		mk(&e, (uint16_t)v);
		e.off_image = kof_evt_text_put(&e, "/usr/bin/image");
		e.off_cmdline = kof_evt_text_put(&e, "image --flag");
		e.off_object = kof_evt_text_put(&e, "/etc/hosts");
		e.loc = kof_classify("/etc/hosts", &e.attack);
		switch (kof_evt_kind_of((uint16_t)v)) {
		case KOF_EK_PROC:
			kof_evt_set_proc(&e)->exit_code = 3;
			kof_evt_set_proc(&e)->session_id = 2;
			kof_evt_set_proc(&e)->create_time = 99;
			break;
		case KOF_EK_MEM:
			kof_evt_set_mem(&e)->addr = 0x7f001000ull;
			kof_evt_set_mem(&e)->addr_size = 4096;
			break;
		case KOF_EK_NET:
			kof_evt_ip_set_v4(kof_evt_set_net(&e)->daddr, 0x0100007fu);
			kof_evt_set_net(&e)->dport = 0x5000;
			kof_evt_set_net(&e)->size = 321;
			break;
		case KOF_EK_FILE:
			kof_evt_set_file(&e)->size = 64;
			kof_evt_set_file(&e)->offset = 34;
			kof_evt_set_file(&e)->key = 0xabc;
			break;
		case KOF_EK_REG:
			kof_evt_set_reg(&e)->type = 1;
			kof_evt_set_reg(&e)->data_size = 100;
			kof_evt_set_reg(&e)->disp = 1;
			e.off_data = kof_evt_text_put(&e, "h\0i\0\0\0");
			e.data_len = 6;
			break;
		default:
			break;
		}
		if (v == KOF_EVT_AMSI_SCAN) {
			e.off_object = e.text_len;
			memcpy(e.text + e.text_len, "Invoke-Expression 'x'", 22);
			e.text_len = (uint16_t)(e.text_len + 22u);
			e.content_len = 21;
		}
		fz_corpus_add_map(c, "evt", &e, sizeof e, &map_evt);
	}
}

static const char *const dict_evt[] = { "/etc/passwd", "\\Device\\NamedPipe\\", "Run", "\x4d\x5a", NULL };

static int run_evt(struct fz_ctx *c, const uint8_t *in, size_t n)
{
	static struct fz_gb gb;
	static int have;
	struct kof_evt *e;
	struct kof_evt_tally t;
	char *buf = NULL;
	size_t blen = 0;
	FILE *f;
	unsigned nf, i;
	char name[64], val[160], lbl[KOF_EVT_LABEL_MAX], wide[200];
	uint16_t off, len;
	const char *ct = NULL;
	size_t cn = 0;
	struct kof_evt_join j;
	unsigned char jb[1024];

	if (!have) {
		if (!fz_gb_init(&gb, sizeof *e, 0, 0))
			return 0;
		have = 1;
	}
	e = (struct kof_evt *)fz_gb_end(&gb, sizeof *e);
	memset(e, 0, sizeof *e);
	memcpy(e, in, n < sizeof *e ? n : sizeof *e);
	ofx_seal(e);

	memset(&t, 0, sizeof t);
	f = open_memstream(&buf, &blen);
	if (!f)
		return 0;
	kof_evt_render(e, 1.5, "who", f, &t);
	kof_evt_print_tally(&t, 1.5, "fuzz", f);
	fclose(f);
	FZ_CHECK(c, e->verb == KOF_EVT_CONT || (blen > 0 && buf[0] != '\0'), "a record that is not a continuation renders no line");
	FZ_CHECK(c, blen < 4096u + 540u * 4u, "a rendered record is unbounded");
	fz_digest(c, blen);
	/* the rendered line may carry a record's own control bytes: kof_evt_render prints paths as written (finding WP12-24, unit row) */
	free(buf);

	nf = kof_evt_n_fields(e);
	FZ_CHECK(c, nf >= 3 && nf < 64, "the number of fields is out of range");
	for (i = 0; i < nf; i++) {
		FZ_CHECK(c, kof_evt_field(e, i, name, sizeof name, val, sizeof val) == 1, "a field below the count is refused");
		off = len = 0;
		FZ_CHECK(c, kof_evt_field_extent(e, i, &off, &len) == 1, "an extent below the count is refused");
		FZ_CHECK(c, (uint32_t)off + len <= sizeof *e, "a field extent reaches past the record");
		FZ_CHECK(c, strlen(name) < sizeof name && strlen(val) < sizeof val, "a field name or value is not terminated");
		fz_digest(c, off ^ ((uint64_t)len << 16));
		if (!fz_step(&c->steps, 1))
			break;
	}
	FZ_CHECK(c, kof_evt_field(e, nf, name, sizeof name, val, sizeof val) == 0, "the field after the last exists");
	FZ_CHECK(c, kof_evt_label(e, 5, lbl, sizeof lbl) < sizeof lbl && strlen(lbl) < KOF_EVT_LABEL_MAX, "a label is not bounded");

	if (kof_evt_content(e, &ct, &cn)) {
		FZ_CHECK(c, cn == 0 || (ct >= e->text && (size_t)(ct - e->text) + cn <= sizeof e->text), "the content span leaves the arena");
		(void)kof_evt_text_of(ct, cn, wide, sizeof wide);
		FZ_CHECK(c, strlen(wide) < sizeof wide, "readable text is not terminated");
		(void)kof_evt_text_is_wide(ct, cn);
		(void)kof_evt_content_looks_binary(e);
		fz_digest(c, cn);
	}
	(void)kof_evt_as_proc(e);
	(void)kof_evt_as_mem(e);
	(void)kof_evt_as_net(e);
	(void)kof_evt_as_file(e);
	(void)kof_evt_as_reg(e);
	FZ_CHECK(c, strlen(kof_evt_image(e)) < sizeof e->text && strlen(kof_evt_object(e)) < sizeof e->text && strlen(kof_evt_cmdline(e)) < sizeof e->text,
		 "a string accessor ran past the arena");
	/* the join: this record as the parent, and as its own continuation */
	if (kof_evt_join_start(&j, e, jb, sizeof jb)) {
		struct kof_evt cont = *e;

		cont.verb = KOF_EVT_CONT;
		cont.seq = e->seq + 1u;
		(void)kof_evt_join_add(&j, &cont);
		FZ_CHECK(c, j.len <= sizeof jb, "the join wrote past its buffer");
		(void)kof_evt_join_whole(&j, e);
		fz_digest(c, j.len);
	}
	{
		char ip[KOF_IP_STR_MAX];
		const struct kof_evt_net *nt = kof_evt_as_net(e);

		if (nt) {
			FZ_CHECK(c, kof_evt_ip_str(nt->daddr, ip, sizeof ip) == ip && strlen(ip) < sizeof ip, "an address string is not bounded");
			(void)kof_evt_ip_is_v6(nt->daddr);
			(void)kof_evt_ip_is_unset(nt->daddr);
		}
	}
	{
		uint16_t att;
		uint8_t loc = kof_classify(kof_evt_object(e), &att);

		fz_digest(c, loc ^ ((uint64_t)att << 8));
		FZ_CHECK(c, loc < KOF_LOC_COUNT && att < KOF_ATT_COUNT, "classification outside its enums");
		(void)kof_classify_path(kof_evt_object(e));
		(void)kof_path_leaf(kof_evt_object(e));
		(void)kof_evt_verb_name(e->verb);
		(void)kof_evt_source_name(e->source);
		(void)kof_loc_name(e->loc);
		(void)kof_attack_id(e->attack);
		(void)kof_attack_name(e->attack);
	}
	return 0;
}

FZ_ADAPTER(evt_record, .name = "orbit/evt_record",
	   .covers = "kof_evt_render kof_evt_print_tally kof_evt_n_fields kof_evt_field kof_evt_field_extent kof_evt_label kof_evt_content kof_evt_text_of kof_evt_text_is_wide "
		     "kof_evt_content_looks_binary kof_evt_as_proc kof_evt_as_mem kof_evt_as_net kof_evt_as_file kof_evt_as_reg kof_evt_image kof_evt_object kof_evt_cmdline "
		     "kof_evt_join_start kof_evt_join_add kof_evt_join_whole kof_evt_ip_str kof_evt_ip_is_v6 kof_evt_ip_is_unset kof_classify kof_classify_path kof_path_leaf "
		     "kof_evt_verb_name kof_evt_source_name kof_loc_name kof_attack_id kof_attack_name",
	   .shape = FZ_REQ, .seeds = seeds_evt, .dict = dict_evt, .run = run_evt);

/* ------------------------------------------------------------------------------------------------- cmdline_norm */

static void seeds_norm(struct fz_corpus *c)
{
	static const uint8_t a[] = "/bin/sh\0-c\0echo hi\0";
	static const uint8_t b[] = "  a \t\r\n b\x7f" "c\xff\xfe  ";

	fz_corpus_add(c, "argv", a, sizeof a - 1u);
	fz_corpus_add(c, "spaces", b, sizeof b - 1u);
	fz_corpus_add(c, "empty", a, 0);
}

static int run_norm(struct fz_ctx *c, const uint8_t *in, size_t n)
{
	char out[600];
	size_t cap = 1u + (size_t)fz_below(c->rng, sizeof out - 1u), w, i;
	char *mid;

	memset(out, 0x55, sizeof out);
	w = kof_cmdline_norm(in, n, out, cap);
	FZ_CHECK(c, w < cap && out[w] == '\0' && strlen(out) == w, "the result is not terminated inside the capacity");
	FZ_CHECK(c, w == 0 || (out[0] != ' ' && out[w - 1u] != ' '), "the result is not trimmed");
	for (i = 0; i + 1u < w; i++)
		FZ_CHECK(c, !(out[i] == ' ' && out[i + 1u] == ' '), "two spaces in a row");
	for (i = 0; i < w; i++)
		FZ_CHECK(c, (unsigned char)out[i] > 0x20u && (unsigned char)out[i] != 0x7fu ? 1 : out[i] == ' ', "a control byte survived");
	mid = out + cap;
	FZ_CHECK(c, cap >= sizeof out || *mid == 0x55, "a byte past the capacity was written");
	fz_digest(c, w);
	for (i = 0; i < w; i++)
		fz_digest(c, (unsigned char)out[i]);
	return (int)w;
}

FZ_ADAPTER(cmdline_norm, .name = "orbit/cmdline_norm", .covers = "kof_cmdline_norm", .shape = FZ_REQ, .seeds = seeds_norm, .run = run_norm);

/* ------------------------------------------------------------------------------------------------- evtlog */

static struct fz_field lfld[16];
static struct fz_map lmap;

static void lfield(uint32_t off, unsigned size, enum fz_fkind kind)
{
	struct fz_field *f = &lfld[lmap.n++];

	f->off = off;
	f->size = (uint8_t)size;
	f->be = 0;
	f->kind = (uint8_t)kind;
}

static void seeds_log(struct fz_corpus *c)
{
	char path[600];
	struct kofevt_log_info info;
	struct kofevt_log_w *w;
	unsigned i, k;
	FILE *f;
	uint8_t *buf;
	long sz;

	memset(&info, 0, sizeof info);
	info.rec_size = sizeof(struct kof_evt);
	info.head_size = KOF_EVT_HEAD;
	info.len_off = (uint16_t)offsetof(struct kof_evt, text_len);
	info.rec_kind = KOFEVT_REC_KOF;
	info.build = 77;
	for (k = 0; k < 4; k++) {
		static const unsigned counts[4] = { 0, 3, 40, 2 };

		snprintf(path, sizeof path, "%s/seed%u.log", ofx_dir(), k);
		w = kofevt_log_create(path, &info);
		for (i = 0; w && i < counts[k]; i++) {
			struct kof_evt e;
			char s[200];
			unsigned q;

			mk(&e, (uint16_t)(1u + i % 20u));
			e.seq = i;
			for (q = 0; q < (i * 13u) % 150u; q++)
				s[q] = (char)('a' + (q + i) % 26u);
			s[q] = '\0';
			e.off_object = kof_evt_text_put(&e, s);
			if (k == 3 && i == 1) {                              /* a full arena with no NUL: the reader must seal it */
				memset(e.text, 'Z', sizeof e.text);
				e.text_len = sizeof e.text;
				e.off_object = 0;
			}
			kofevt_log_write(w, &e);
		}
		kofevt_log_close(w);
		f = fopen(path, "rb");
		if (!f)
			continue;
		fseek(f, 0, SEEK_END);
		sz = ftell(f);
		fseek(f, 0, SEEK_SET);
		buf = (uint8_t *)malloc((size_t)sz);
		if (buf && fread(buf, 1, (size_t)sz, f) == (size_t)sz) {
			lmap.f = lfld;
			lmap.n = 0;
			lfield(0, 4, FZ_OFFSET);                                            /* magic */
			lfield(4, 2, FZ_COUNT);                                             /* version */
			lfield(6, 2, FZ_OFFSET);                                            /* hdr_size */
			lfield(8, 4, FZ_LEN);                                               /* rec_size */
			lfield((uint32_t)offsetof(struct kofevt_log_hdr, n_records), 8, FZ_COUNT);
			lfield((uint32_t)offsetof(struct kofevt_log_hdr, head_size), 2, FZ_LEN);
			lfield((uint32_t)offsetof(struct kofevt_log_hdr, len_off), 2, FZ_OFFSET);
			lfield((uint32_t)offsetof(struct kofevt_log_hdr, rec_kind), 2, FZ_COUNT);
			if (sz > (long)(64 + KOF_EVT_HEAD))
				lfield(64u + (uint32_t)offsetof(struct kof_evt, text_len), 2, FZ_LEN);   /* the first record's own length */
			fz_corpus_add_map(c, "log", buf, (size_t)sz, &lmap);
		}
		free(buf);
		fclose(f);
		unlink(path);
	}
}

struct logh {
	struct kofevt_log_r *r;
	uint64_t             fsize;
};

static void *parse_log(struct fz_ctx *c, const uint8_t *in, size_t n)
{
	char path[64];
	int fd = ofx_memfd(in, n, path, sizeof path);
	struct logh *h;
	const char *why = "";

	if (fd < 0)
		return NULL;
	h = (struct logh *)malloc(sizeof *h);
	if (!h) {
		close(fd);
		return NULL;
	}
	h->fsize = n;
	h->r = kofevt_log_open(path, 0, KOFEVT_REC_NONE, &why);
	close(fd);
	FZ_CHECK(c, why != NULL, "no reason string");
	if (!h->r) {
		free(h);
		fz_digest(c, 0xdead);
		return NULL;
	}
	return h;
}

static void walk_log(struct fz_ctx *c, void *hh, const uint8_t *in, size_t n)
{
	struct logh *h = (struct logh *)hh;
	const struct kofevt_log_hdr *hd = kofevt_log_header(h->r);
	uint8_t *rec;
	uint64_t cnt, rd = 0, off;
	uint32_t len;
	unsigned i;

	(void)in;
	FZ_CHECK(c, hd && hd->magic == KOFEVT_LOG_MAGIC && hd->version == KOFEVT_LOG_VERSION, "an opened log whose header is not a header");
	FZ_CHECK(c, hd->rec_size && hd->rec_size <= 65536u && hd->head_size && hd->head_size <= hd->rec_size && (uint32_t)hd->len_off + 2u <= hd->head_size,
		 "an opened log with an impossible shape");
	rec = (uint8_t *)malloc(hd->rec_size);
	if (!rec)
		return;
	while (rd < 100000 && kofevt_log_read(h->r, rec, hd->rec_size) == 1) {
		uint16_t tl;

		memcpy(&tl, rec + hd->len_off, 2);
		FZ_CHECK(c, (uint32_t)hd->head_size + tl <= hd->rec_size, "a record that was read claims a text past its record");
		FZ_CHECK(c, hd->rec_size == hd->head_size || rec[hd->rec_size - 1u] == '\0', "the arena of a record that was read does not end in NUL");
		rd++;
		if (!fz_step(&c->steps, 1))
			break;
	}
	FZ_CHECK(c, rd * hd->head_size <= h->fsize + hd->head_size, "more records were read than the file can hold");
	cnt = kofevt_log_count(h->r);
	if (hd->n_records)
		FZ_CHECK(c, cnt == hd->n_records, "the count is not the header's number");
	fz_digest(c, rd ^ (cnt << 20));
	for (i = 0; i < 6; i++) {
		uint64_t at = cnt ? (uint64_t)fz_below(c->rng, cnt > 4000 ? 4000 : cnt) : 0;

		if (kofevt_log_seek(h->r, at)) {
			if (kofevt_log_extent(h->r, at, &off, &len))
				FZ_CHECK(c, len >= hd->head_size && len <= hd->rec_size && off >= hd->hdr_size / 2, "an extent that is not a place in the file");
			(void)kofevt_log_read(h->r, rec, hd->rec_size);
		}
	}
	(void)n;
	free(rec);
}

static void drop_log(void *hh)
{
	struct logh *h = (struct logh *)hh;

	kofevt_log_free(h->r);
	free(h);
}

FZ_ADAPTER(evtlog, .name = "orbit/evtlog",
	   .covers = "kofevt_log_create kofevt_log_write kofevt_log_close kofevt_log_open kofevt_log_header kofevt_log_read kofevt_log_count kofevt_log_seek kofevt_log_extent kofevt_log_free",
	   .shape = FZ_PARSE, .flags = FZ_MAY_HIT_CAP, .backstop_s = 1800, .seeds = seeds_log, .parse = parse_log, .walk = walk_log, .drop = drop_log);
