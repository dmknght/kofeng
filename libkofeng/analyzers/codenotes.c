/*
 * codenotes.c - kof_codenotes_build. See codenotes.h for what a note is and why a scan never makes one.
 *
 * Names come from three places and only these: the symbol block (a function that starts at an offset), the relocation table (the symbol a module's
 * call is patched to), and the syscall vocabulary (a number's name). An address nothing names is shown as the address - `fcn_<offset>` for an entry
 * the code calls, `.L-<offset>` for a jump's landing - and never as a guess at what it is.
 */

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

#include "../kofcore/tabgrow.h"
#include <string.h>

#include <kofmod/elf.h>
#include <celllysis/nucleo.h>
#include <genotype/image/elf_image.h>
#include <phenotype/codemap.h>

#include "callnames.h"
#include "codenotes.h"
#include "genome_obj.h"
#include "parsers/binaries/funcs.h"

/* The most xrefs a label's text lists. The TABLE keeps every reference; this bounds one line of text a person reads. */
#define NOTE_XREFS 6u

struct nb {
	struct kof_codenotes *out;
	uint32_t cap;
	uint64_t pcap;
	int fail;
	const struct kgenome_codemap *cm;
	const struct kgenome_func_set *funcs;
	const uint8_t *sym;
	uint32_t sym_n;
	kof_buf data;
	const struct kgenome_callnames *names;
	unsigned arch;
	int format;
};

static void note_add(struct nb *b, uint64_t at, unsigned kind, const char *fmt, ...)
{
	struct kof_codenotes *o = b->out;
	char tmp[512];
	va_list ap;
	int w;
	size_t need;

	if (b->fail)
		return;
	va_start(ap, fmt);
	w = vsnprintf(tmp, sizeof tmp, fmt, ap);
	va_end(ap);
	if (w < 0)
		return;
	if ((size_t)w >= sizeof tmp)
		w = (int)sizeof tmp - 1;
	need = (size_t)o->pool_n + (size_t)w + 1u;
	if (need > b->pcap) {
		uint64_t nc = b->pcap ? b->pcap * 2u : 4096u;
		char *np;

		while (nc < need)
			nc *= 2u;
		np = realloc(o->pool, (size_t)nc);
		if (!np) {
			b->fail = 1;
			return;
		}
		o->pool = np;
		b->pcap = nc;
	}
	if (o->n == b->cap) {
		uint32_t nc = kof_cap_double(b->cap, 256u);
		struct kof_note *nv = nc ? realloc(o->v, (size_t)nc * sizeof *nv) : NULL;

		if (!nv) {
			b->fail = 1;
			return;
		}
		o->v = nv;
		b->cap = nc;
	}
	memcpy(o->pool + o->pool_n, tmp, (size_t)w + 1u);
	o->v[o->n++] = (struct kof_note){ at, o->pool_n, (uint8_t)kind };
	o->pool_n += (uint32_t)w + 1u;
}

/* What a place is called: a function of the table by kof_func_name (its symbol, else `fcn_<offset>`: the ONE spelling, the CFG dialog's too); an entry the
 * code calls that the table lacks by kof_fcn_name; else the jump label `.L-<offset>`, which is not a function and is spelled here. */
static void place_name(const struct nb *b, uint64_t off, int entry, char *out, size_t cap)
{
	uint32_t i;

	if (b->names && kof_callnames_name(b->names, b->data, KOF_CALLNAME_VIA_TARGET, off, out, cap))
		return;
	i = kgenome_funcs_start(b->funcs, off);
	if (i != KGENOME_FUNCS_NONE)
		(void)kof_func_name(&b->funcs->v[i], b->sym, b->sym_n, out, cap);
	else if (entry)
		kof_fcn_name(off, out, cap);
	else
		snprintf(out, cap, ".L-%llx", (unsigned long long)off);
}

static const char *kind_word(unsigned k)
{
	return k == KGENOME_CM_CALL ? "call" : k == KGENOME_CM_JMP ? "jmp" : k == KGENOME_CM_LOOP ? "loop" : "jcc";
}

/* "  ; xrefs: 1051 call, 103a jmp" for the references to `to`, or nothing. */
static void xref_text(const struct nb *b, uint64_t to, char *out, size_t cap)
{
	uint32_t first, n = kgenome_codemap_to(b->cm, to, &first), k;
	size_t w = 0;

	out[0] = 0;
	for (k = 0; k < n && k < NOTE_XREFS && w + 1u < cap; k++) {
		const struct kgenome_codemap_ref *r = &b->cm->v[b->cm->by_to[first + k]];

		w += (size_t)snprintf(out + w, cap - w, "%s%llx %s", k ? ", " : "  ; xrefs: ",
				      (unsigned long long)r->at, kind_word(r->kind));
	}
	if (n > NOTE_XREFS && w + 1u < cap)
		snprintf(out + w, cap - w, ", +%u more", n - NOTE_XREFS);
}

/* The name a module's relocation gives the branch at `at`: the relocation's symbol, read from the object's own bytes. */
static int reloc_name(const struct kgenome_elf_relocs *t, kof_buf d, const struct kgenome_codemap_ref *r, char *out, size_t cap)
{
	const struct kgenome_elf_reloc *x = t ? kgenome_elf_reloc_in(t, r->at, r->len) : NULL;
	size_t k;

	if (!x || !x->nameoff || x->nameoff >= d.n)
		return 0;
	for (k = 0; k + 1u < cap && x->nameoff + k < d.n && d.p[x->nameoff + k]; k++)
		out[k] = (char)d.p[x->nameoff + k];
	out[k] = 0;
	return k != 0;
}

/*
 * The label rows: every function the table names (FUNC), and every other place something branches to (LABEL). A FUNC is what the function table says is one: a call target
 * the table does not hold is not a function here (the table is the one answer to "where are the functions"; it was `entry |= kind == CALL`, which listed an entry the table had
 * merged away inside a body as a second function). Such a place is a LABEL, spelled as the call that reaches it spells it (`fcn_<offset>`, place_name), so the label and
 * the call site read alike. Labels for jump landings (.L-<offset>) are not function extents and stay a naming of codemap places.
 */
static void add_places(struct nb *b)
{
	const struct kgenome_codemap *m = b->cm;
	uint32_t i, k;
	char nm[160], xr[200];

	for (i = 0; i < b->funcs->n; i++) {
		(void)kof_func_name(&b->funcs->v[i], b->sym, b->sym_n, nm, sizeof nm);     /* its symbol, else `fcn_<offset>` */
		xref_text(b, b->funcs->v[i].off, xr, sizeof xr);
		note_add(b, b->funcs->v[i].off, KOF_NOTE_FUNC, "%s:%s", nm, xr);
	}
	/* by_to is ordered by (to, at): a place is met once, with all its references together. */
	for (k = 0; k < m->n_to; k++) {
		const struct kgenome_codemap_ref *r = &m->v[m->by_to[k]];
		uint32_t first, cnt;
		int called = 0;
		uint32_t j;

		if (k && m->v[m->by_to[k - 1u]].to == r->to)
			continue;
		if (kgenome_funcs_start(b->funcs, r->to) != KGENOME_FUNCS_NONE)
			continue;                       /* a function of the table: its FUNC note was written above */
		cnt = kgenome_codemap_to(m, r->to, &first);
		for (j = 0; j < cnt; j++)
			called |= m->v[m->by_to[first + j]].kind == KGENOME_CM_CALL;
		xref_text(b, r->to, xr, sizeof xr);
		/* an import stub the object's call-name table names (`rand@plt`) is a function though the table has no entry for it */
		if (b->names && kof_callnames_name(b->names, b->data, KOF_CALLNAME_VIA_TARGET, r->to, nm, sizeof nm)) {
			note_add(b, r->to, KOF_NOTE_FUNC, "%s:%s", nm, xr);
		} else {
			place_name(b, r->to, called, nm, sizeof nm);
			note_add(b, r->to, KOF_NOTE_LABEL, "%s:%s", nm, xr);
		}
	}
}

/* The name of a syscall number on this object, "" when the vocabulary has none for it. */
static const char *sys_name(const struct nb *b, const struct kgenome_codemap_ref *r)
{
	const struct kgenome_nucleo_abi *fx;

	if (b->arch == KGENOME_ARCH_X86 || b->arch == KGENOME_ARCH_X86_64) {
		unsigned bits = (r->flags & KGENOME_CMF_INT80) || b->arch == KGENOME_ARCH_X86 ? 32u : 64u;
		const char *nm = kgenome_nucleo_sys_name_all(bits, r->nr);

		return nm ? nm : "";
	}
	fx = kgenome_nucleo_abi_of(b->arch);
	return fx && kgenome_nucleo_sys_name_abi(fx, r->nr) ? kgenome_nucleo_sys_name_abi(fx, r->nr) : "";
}

/*
 * A SYSCALL'S COMMENT. The vocabulary is Linux's, and a number means that only where the object is Linux's to say so: an ELF. A PE's `syscall` carries
 * a Windows service number (0x3b there is not execve), so it gets the number and no name; a blob with no header could be either, so its name is
 * given with the word that says whose table it came from.
 */
static void add_syscall(struct nb *b, const struct kgenome_codemap_ref *r)
{
	const char *nm;

	if (!(r->flags & KGENOME_CMF_NR)) {
		note_add(b, r->at, KOF_NOTE_COMMENT, "syscall, number not known here");
		return;
	}
	nm = b->format == KOF_FMT_PE ? "" : sys_name(b, r);
	if (!nm[0])
		note_add(b, r->at, KOF_NOTE_COMMENT, "syscall %u", r->nr);
	else if (b->format == KOF_FMT_ELF)
		note_add(b, r->at, KOF_NOTE_COMMENT, "%s (%u)", nm, r->nr);
	else
		note_add(b, r->at, KOF_NOTE_COMMENT, "linux: %s (%u)", nm, r->nr);
}

static void add_branch(struct nb *b, const struct kgenome_codemap_ref *r, const struct kgenome_elf_relocs *rel)
{
	char nm[160];
	const char *loop = (r->flags & KGENOME_CMF_BACK) && r->kind != KGENOME_CM_CALL ? " (backward)" : "";

	if (reloc_name(rel, b->data, r, nm, sizeof nm))
		note_add(b, r->at, KOF_NOTE_COMMENT, "-> %s", nm);
	else if (b->names && (r->flags & KGENOME_CMF_INDIRECT) &&
		 kof_callnames_name(b->names, b->data, KOF_CALLNAME_VIA_SITE, r->at, nm, sizeof nm))
		note_add(b, r->at, KOF_NOTE_COMMENT, "-> %s", nm);
	else if (r->to != KGENOME_BROKEN) {
		place_name(b, r->to, r->kind == KGENOME_CM_CALL || kgenome_funcs_start(b->funcs, r->to) != KGENOME_FUNCS_NONE, nm, sizeof nm);
		note_add(b, r->at, KOF_NOTE_COMMENT, "-> %s%s", nm, loop);
	}
}

static int note_cmp(const void *a, const void *c)
{
	const struct kof_note *x = a, *y = c;

	if (x->at != y->at)
		return x->at < y->at ? -1 : 1;
	return (int)x->kind - (int)y->kind;
}

/* THE ADAPTER KEPT FOR kofexamine (parked, its caller still has this shape): the same, with no walk and no relocation table of the caller's. Delete it when the examiner moves to the request. */
int kof_codenotes_build(const struct kof_obj_ctx *ctx, kof_buf data, const struct kgenome_func_set *funcs,
			const uint8_t *sym, uint32_t sym_n, unsigned bits, const struct kgenome_callnames *names,
			struct kof_codenotes *out)
{
	const struct kof_codenotes_req rq = { .ctx = ctx, .data = data, .funcs = funcs, .sym = sym, .sym_n = sym_n, .bits = bits, .names = names };

	return kof_codenotes_make(&rq, out);
}

int kof_codenotes_make(const struct kof_codenotes_req *rq, struct kof_codenotes *out)
{
	const struct kof_obj_ctx *ctx = rq->ctx;
	const kof_buf data = rq->data;
	const unsigned bits = rq->bits;
	struct kgenome_obj gobj;
	struct kgenome_codemap cm;
	struct kgenome_elf_relocs rel;
	const struct kgenome_elf_relocs *rp = rq->relocs;
	struct nb b;
	uint32_t i;
	int have_rel = 0;

	memset(out, 0, sizeof *out);
	memset(&rel, 0, sizeof rel);
	kof_genome_obj(ctx, &gobj);
	if (bits && gobj.arch != KGENOME_ARCH_X86 && gobj.arch != KGENOME_ARCH_X86_64 && gobj.format == KGENOME_FMT_NONE)
		gobj.arch = bits == 32u ? KGENOME_ARCH_X86 : KGENOME_ARCH_X86_64;
	if (!rp && gobj.format == KGENOME_FMT_ELF && kgenome_obj_elf(&gobj) && kgenome_obj_elf(&gobj)->valid) {
		(void)kgenome_elf_reloc_table(data, kgenome_obj_elf(&gobj), KGENOME_ELF_RELOC_CODE, &rel);
		have_rel = 1;
		rp = rel.n ? &rel : NULL;
	}
	/* The codemap is one linear read of the code: given the object's walk (`wk`) it READS the walk's trace and decodes nothing; with none it decodes (the adapter above). */
	/* KNOWN DEFECT D18b (2026-10-24, R) [sev L]: through kof_codenotes_build (kofexamine, parked) the codemap and the relocation table are made again, a scan's lineage builds another.
	 * Trigger: the examiner's disasm panel on an object a scan already analysed. Effect: work done twice, and two tables of one fact; narrowed 2026-11-03: kof_codenotes_make takes the walk.
	 * Reproducer: none (read, STATUS D12/D18). Fix: the examiner calls kof_codenotes_make with the object's walk and relocations; then delete the adapter. */
	if (!kgenome_codemap_build(&gobj, data.p, data.n, rp, rq->wk, &cm)) {
		out->status = cm.status;
		if (have_rel)
			kgenome_elf_reloc_table_free(&rel);
		return 0;
	}
	memset(&b, 0, sizeof b);
	b.out = out;
	b.cm = &cm;
	b.funcs = rq->funcs;
	b.sym = rq->sym;
	b.sym_n = rq->sym_n;
	b.data = data;
	b.names = rq->names;
	b.arch = gobj.arch;
	b.format = (int)gobj.format;
	add_places(&b);
	for (i = 0; i < cm.n; i++) {
		const struct kgenome_codemap_ref *r = &cm.v[i];

		if (r->kind == KGENOME_CM_SYSCALL)
			add_syscall(&b, r);
		else if (r->kind != KGENOME_CM_RET)
			add_branch(&b, r, rp);
	}
	if (out->n > 1u)
		qsort(out->v, out->n, sizeof *out->v, note_cmp);
	kgenome_codemap_free(&cm);
	if (have_rel)
		kgenome_elf_reloc_table_free(&rel);
	if (b.fail) {
		kof_codenotes_free(out);
		out->status = KGENOME_NOMEM;
		return 0;
	}
	return 1;
}

void kof_codenotes_free(struct kof_codenotes *n)
{
	free(n->v);
	free(n->pool);
	memset(n, 0, sizeof *n);
}

const struct kof_note *kof_codenotes_at(const struct kof_codenotes *n, uint64_t at, uint32_t *count)
{
	uint32_t lo = 0, hi = n->n, k = 0;

	while (lo < hi) {
		uint32_t mid = lo + (hi - lo) / 2u;

		if (n->v[mid].at < at)
			lo = mid + 1u;
		else
			hi = mid;
	}
	while (lo + k < n->n && n->v[lo + k].at == at)
		k++;
	*count = k;
	return k ? &n->v[lo] : NULL;
}
