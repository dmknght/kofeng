/*
 * image/pe_parse - the PE reader of kgenome and every walk of the parsed object: kgenome_pe_image_parse, the import and
 * export walks, the import table builder and its name reader, kgenome_pe_sniff.
 *
 * Seeds are the objects tests/lib/genome/hk.h builds (PE32 and PE32+, three sections, imports by name and by ordinal,
 * an export directory). The field map comes from the offsets the builder publishes, so the mutators aim at e_lfanew,
 * the section count, the optional header size, the data directories, the section headers and the import / export
 * descriptors by name, and reorder or duplicate the section records.
 * Held: the callbacks never report a byte outside the object, the status of a bounded walk is in the enum and the counts
 * the walks return are the counts the callbacks saw, the table builder and the visitor agree, and the clamped section
 * count does not exceed the claimed one.
 */
#include <kgenome.h>

#include "../../lib/genome/hk.h"
#include "../../lib/fuzz_drv.h"

static struct fz_field fld[2][40];
static struct fz_map map[2];

static void field(unsigned v, uint32_t off, unsigned size, enum fz_fkind kind)
{
	struct fz_field *f = &fld[v][map[v].n++];

	f->off = off;
	f->size = (uint8_t)size;
	f->be = 0;
	f->kind = (uint8_t)kind;
}

static void seed_one(struct fz_corpus *c, const char *name, int plus)
{
	static struct hk_pe p[2];
	struct hk_pe *q = &p[plus];
	unsigned v = (unsigned)plus, i;

	hk_pe(q, plus);
	map[v].f = fld[v];
	map[v].n = 0;
	field(v, 0x3c, 4, FZ_OFFSET);
	field(v, q->lfanew + 6u, 2, FZ_COUNT);
	field(v, q->lfanew + 20u, 2, FZ_LEN);
	field(v, q->opt + 16u, 4, FZ_RVA);
	field(v, q->opt + 32u, 4, FZ_LEN);
	field(v, q->opt + 36u, 4, FZ_LEN);
	field(v, q->opt + 56u, 4, FZ_LEN);
	field(v, q->opt + 60u, 4, FZ_LEN);
	field(v, q->opt + (plus ? 108u : 92u), 4, FZ_COUNT);
	for (i = 0; i < 4; i++)                                   /* export, import directories: RVA and size */
		field(v, q->dirs + 4u * i, 4, i % 2u ? FZ_LEN : FZ_RVA);
	for (i = 0; i < 3; i++) {
		field(v, q->sec + 40u * i + 8u, 4, FZ_LEN);
		field(v, q->sec + 40u * i + 12u, 4, FZ_RVA);
		field(v, q->sec + 40u * i + 16u, 4, FZ_LEN);
		field(v, q->sec + 40u * i + 20u, 4, FZ_OFFSET);
	}
	for (i = 0; i < 4; i++)                                   /* the first import descriptors */
		field(v, q->imp_off + 4u * i, 4, FZ_RVA);
	field(v, q->imp_off + 12u, 4, FZ_RVA);
	field(v, q->imp_off + 16u, 4, FZ_RVA);
	for (i = 0; i < 4; i++)                                   /* the export directory: counts and table RVAs */
		field(v, q->exp_off + 20u + 4u * i, 4, i < 2 ? FZ_COUNT : FZ_RVA);
	field(v, q->exp_off + 36u, 4, FZ_RVA);
	map[v].rec_off = q->sec;
	map[v].rec_size = 40;
	map[v].rec_n = 3;
	fz_corpus_add_map(c, name, q->b, q->n, &map[v]);
}

static void seeds(struct fz_corpus *c)
{
	seed_one(c, "pe32", 0);
	seed_one(c, "pe32plus", 1);
}

static const char *const dict[] = { "MZ", "PE\0\0", ".text", "kernel32.dll", "ExitProcess", NULL };

struct st {
	struct kgenome_pe_info info;
	struct kgenome_obj     obj;
};

static struct st state;

struct acc {
	struct fz_ctx *c;
	uint64_t       n;
	uint32_t       calls;
};

static void imp_cb(void *u, uint64_t slot, const char *dll, const char *name, uint32_t ordinal, uint64_t nameoff)
{
	struct acc *a = (struct acc *)u;

	(void)slot;
	a->calls++;
	fz_step(&a->c->steps, 1);
	FZ_CHECK(a->c, dll && strlen(dll) <= 4095u, "an import without a library name");
	FZ_CHECK(a->c, !nameoff || nameoff == KGENOME_BROKEN || nameoff < a->n, "an import name offset outside the object");
	FZ_CHECK(a->c, !nameoff || (name && strlen(name) <= 4095u), "an import with an offset and no name");
	fz_digest(a->c, ordinal + a->calls);
}

static int exp_cb(void *u, uint64_t nameoff, uint32_t rva)
{
	struct acc *a = (struct acc *)u;

	a->calls++;
	fz_step(&a->c->steps, 1);
	FZ_CHECK(a->c, nameoff < a->n, "an export name offset outside the object");
	fz_digest(a->c, rva);
	return 1;
}

static void *parse(struct fz_ctx *c, const uint8_t *in, size_t n)
{
	kof_buf f = kof_buf_make(in, n);

	memset(&state, 0, sizeof state);
	(void)kgenome_pe_sniff(f);
	if (!kgenome_pe_image_parse(f, &state.info, &state.obj)) {
		fz_digest(c, 0xdead);
		return NULL;
	}
	return &state;
}

static void walk(struct fz_ctx *c, void *h, const uint8_t *in, size_t n)
{
	struct st *s = (struct st *)h;
	kof_buf f = kof_buf_make(in, n);
	enum kgenome_status ist = KGENOME_OK, est = KGENOME_OK;
	struct acc ia, ea;
	struct kgenome_pe_imptab t;
	uint32_t got, gote, i;
	char name[KGENOME_PE_IMP_DLLLEN];

	FZ_CHECK(c, s->info.nsec <= s->info.nsec_claimed, "clamped section count above the claimed one");
	FZ_CHECK(c, s->info.entry_sec <= s->info.nsec, "entry section index past the table");
	fz_digest(c, s->info.nsec + ((uint64_t)s->info.nsec_claimed << 16) + (s->info.entry_rva << 32));
	ia.c = ea.c = c;
	ia.n = ea.n = n;
	ia.calls = ea.calls = 0;
	got = kgenome_pe_imports(f, &s->info, imp_cb, &ia, &ist);
	FZ_CHECK(c, got == ia.calls, "kgenome_pe_imports returned a count other than the callbacks seen");
	FZ_CHECK(c, (unsigned)ist <= (unsigned)KGENOME_NOMEM, "import status outside the enum");
	FZ_CHECK(c, (uint64_t)got <= n / (s->info.pe32_plus ? 8u : 4u), "more imports than the file can hold thunks");
	gote = kgenome_pe_exports(f, &s->info, exp_cb, &ea, &est);
	FZ_CHECK(c, gote == ea.calls, "kgenome_pe_exports returned a count other than the callbacks seen");
	FZ_CHECK(c, (unsigned)est <= (unsigned)KGENOME_NOMEM, "export status outside the enum");
	memset(&t, 0, sizeof t);
	kgenome_pe_imptab_build(f, &s->info, &t);
	FZ_CHECK(c, kgenome_pe_imptab_is_of(&t, f), "the table is not of the buffer it was built from");
	FZ_CHECK(c, t.status != KGENOME_OK || t.n == got || ist != KGENOME_OK, "table and walk disagree on the number of imports");
	for (i = 0; i < t.n && i < 64u; i++) {
		uint32_t l = kgenome_pe_imp_name(f, &t.v[i], name, sizeof name);

		FZ_CHECK(c, l < sizeof name, "an import name longer than its buffer");
		FZ_CHECK(c, t.v[i].dll < t.n_dll || !t.n_dll, "an import names a library past the list");
	}
	kgenome_pe_imptab_free(&t);
	fz_digest(c, ((uint64_t)got << 20) ^ gote ^ ((uint64_t)ist << 50));
}

FZ_ADAPTER(pe_parse, .name = "kgenome/pe_image", .covers = "kgenome_pe_image_parse kgenome_pe_sniff kgenome_pe_imports kgenome_pe_exports "
	   "kgenome_pe_imptab_build kgenome_pe_imptab_free kgenome_pe_imptab_is_of kgenome_pe_imp_name",
	   .shape = FZ_PARSE, .seeds = seeds, .dict = dict, .parse = parse, .walk = walk);
