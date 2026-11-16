/*
 * lineage_keep - THE NODE TABLE WHEN IT IS FULL (fix_lgtab, diag_hit.c kgenome_diag_nodes_keep). A constructed system-call program: the stager
 * shape (mmap, socket, connect, nanosleep, a read whose number is connect's result, a jump into the region) after a system call whose number
 * cannot be read (a node with no capability), and after it unlinked noise (six `socket` calls nothing uses), scanned with nine slots:
 *   - the table refuses four noise nodes (counted: refused 4) and the scan goes on - the lineage still runs (a halt used to end it);
 *   - the keep rule then drops what is on no link: nanosleep and the two noise sockets in the table (unlinked 3) and the capability-less
 *     node (nocap 1);
 *   - every link of the stager survives, renumbered: read's buffer and descriptor, its NUMBER from connect, the jump's TARGET;
 *   - a capability a loaded diagnose names is kept even unlinked (keep_caps = { net-open }: the two noise sockets stay, unlinked 1).
 * With a table that does not fill, nothing is refused or dropped and the nanosleep stays.
 */
#include "lineage_check.h"
#include "lineage_raw.h"
#include <phenotype/diag_private.h>

#define EXPECT(cond, ...) do { if (!(cond)) { printf("FAIL " __VA_ARGS__); printf("\n"); hk_fails++; } } while (0)

struct at { uint32_t mmap, sock, conn, sleep, read, jmp; };

static void build(struct rawelf *e, struct at *o)
{
	uint32_t jok, ok, i;

	re_init(e, 1);
	re_b(e, "58 0f 05");                                                     /* pop rax; syscall: a number no one can read - a node with no capability */
	re_b(e, "31 ff be 00 10 00 00 ba 07 00 00 00 41 ba 22 00 00 00 49 c7 c0 ff ff ff ff 45 31 c9 b8 09 00 00 00");
	o->mmap = re_here(e);
	re_b(e, "0f 05 50");                                                     /* mmap; push rax */
	re_b(e, "bf 02 00 00 00 be 01 00 00 00 31 d2 b8 29 00 00 00");
	o->sock = re_here(e);
	re_b(e, "0f 05 48 89 c7");                                               /* socket; mov rdi, rax */
	re_b(e, "57 6a 00 6a 05 48 89 e7 31 f6 b8 23 00 00 00");
	o->sleep = re_here(e);
	re_b(e, "0f 05 59 59 5f");                                               /* nanosleep (unlinked); pop; pop; pop rdi */
	re_b(e, "6a 00 48 89 e6 ba 10 00 00 00 b8 2a 00 00 00");
	o->conn = re_here(e);
	re_b(e, "0f 05 59 48 85 c0 79 00");                                      /* connect; pop rcx; test; jns ok */
	jok = re_here(e) - 1u;
	re_b(e, "b8 3c 00 00 00 0f 05");                                         /* exit */
	ok = re_here(e);
	re_b(e, "5e ba 00 01 00 00");                                            /* ok: pop rsi */
	o->read = re_here(e);
	re_b(e, "0f 05");                                                       /* read: the number is connect's 0 */
	o->jmp = re_here(e);
	re_b(e, "ff e6");                                                       /* jmp rsi */
	for (i = 0; i < 6u; i++)                                                /* the noise: sockets nothing uses */
		re_b(e, "bf 02 00 00 00 be 01 00 00 00 31 d2 b8 29 00 00 00 0f 05");
	re_fix8(e, jok, ok);
	re_finish(e);
}

static struct kgenome_diag_scan *scan(const struct rawelf *e, struct kgenome_elf_info *ei, struct kgenome_obj *o, uint32_t max_nodes,
				      const uint16_t *keep, uint32_t n_keep)
{
	struct kgenome_diag_inputs in;
	static struct kgenome_budget kb;

	memset(o, 0, sizeof *o);
	memset(&in, 0, sizeof in);
	if (!kgenome_elf_image_parse(kof_buf_make(e->b, e->n), ei, o))
		return NULL;
	o->file_header = ei;
	kgenome_budget_default(&kb, e->n, e->n);
	if (max_nodes)
		kb.max_nodes = max_nodes;
	in.budget = &kb;
	in.keep_caps = keep;
	in.n_keep_caps = n_keep;
	return kgenome_diag_scan_with_inputs(o, e->b, e->n, KGENOME_DIAG_RUN_SYSCALL | KGENOME_DIAG_RUN_LINEAGE, &in);
}

static int node_at(const struct kgenome_diag_scan *s, uint64_t at, uint32_t *idx)
{
	uint32_t i;

	for (i = 0; i < kgenome_diag_scan_count(s); i++)
		if (kgenome_diag_scan_at(s, i)->at == at && kgenome_diag_scan_at(s, i)->cap != KGENOME_NUCLEO_NONE) {
			*idx = i;
			return 1;
		}
	return 0;
}

static int how(const struct kgenome_diag_scan *s, uint64_t cat, uint64_t pat, unsigned role)
{
	uint32_t c, p, k;

	if (!node_at(s, cat, &c) || !node_at(s, pat, &p))
		return -2;
	for (k = 0; k < kgenome_diag_in_count(s, c); k++) {
		const struct kgenome_diag_in *x = kgenome_diag_in_at(s, c, k);

		if (x->from == p && x->role == role && x->kind == KGENOME_DIAG_KIND_PRODUCED)
			return x->how;
	}
	return -1;
}

static void the_links(const struct kgenome_diag_scan *s, const struct at *o, const char *what)
{
	EXPECT(how(s, o->read, o->mmap, KGENOME_DIAG_ROLE_BUFFER) == KGENOME_DIAG_LINK_PROVEN, "%s: read buffer <- mmap", what);
	EXPECT(how(s, o->read, o->sock, KGENOME_DIAG_ROLE_FD) == KGENOME_DIAG_LINK_PROVEN, "%s: read fd <- socket", what);
	EXPECT(how(s, o->read, o->conn, KGENOME_DIAG_ROLE_NUMBER) == KGENOME_DIAG_LINK_PROVEN, "%s: read number <- connect", what);
	EXPECT(how(s, o->jmp, o->mmap, KGENOME_DIAG_ROLE_TARGET) == KGENOME_DIAG_LINK_PROVEN, "%s: jump target <- mmap", what);
	EXPECT(how(s, o->conn, o->sock, KGENOME_DIAG_ROLE_FD) == KGENOME_DIAG_LINK_PROVEN, "%s: connect fd <- socket", what);
}

int main(int argc, char **argv)
{
	static struct rawelf e;
	struct kgenome_elf_info ei;
	struct kgenome_obj o;
	struct kgenome_diag_scan *s;
	struct kgenome_diag_drops d;
	struct at a;
	uint32_t x;
	const uint16_t keep[1] = { KGENOME_NUCLEO_NET_OPEN };

	hk_args(argc, argv);
	build(&e, &a);
	/* a table that does not fill: nothing refused, nothing dropped, the unlinked nodes stay */
	s = scan(&e, &ei, &o, 0, NULL, 0);
	CK(s != NULL);
	if (s) {
		kgenome_diag_scan_drops(s, &d);
		EXPECT(d.refused == 0 && d.unlinked == 0 && d.nocap == 0, "roomy: nothing dropped (%u %u %u)", d.refused, d.unlinked, d.nocap);
		EXPECT(node_at(s, a.sleep, &x), "roomy: the unlinked nanosleep stays");
		EXPECT(kgenome_diag_scan_count(s) >= 13u, "roomy: %u nodes", kgenome_diag_scan_count(s));
		the_links(s, &a, "roomy");
		kgenome_diag_scan_free(s);
	}
	/* nine slots: three noise sockets refused, the scan goes on, the keep rule drops the four unlinked nodes */
	s = scan(&e, &ei, &o, 9u, NULL, 0);
	CK(s != NULL);
	if (s) {
		kgenome_diag_scan_drops(s, &d);
		EXPECT(d.refused == 4u && d.unlinked == 3u && d.nocap == 1u, "full: refused 4, unlinked 3, nocap 1 (%u %u %u)", d.refused, d.unlinked,
		       d.nocap);
		EXPECT(kgenome_diag_scan_status(s) != KGENOME_OK, "full: the scan says a node was not kept");
		EXPECT(!node_at(s, a.sleep, &x), "full: the unlinked nanosleep is dropped");
		EXPECT(kgenome_diag_scan_count(s) == 5u, "full: 5 nodes kept (%u)", kgenome_diag_scan_count(s));
		{
			uint32_t q;

			for (q = 0; q < kgenome_diag_scan_count(s); q++)
				EXPECT(kgenome_diag_scan_at(s, q)->cap != KGENOME_NUCLEO_NONE, "full: no capability-less node kept");
		}
		the_links(s, &a, "full");
		kgenome_diag_scan_free(s);
	}
	/* the same, with net-open named by a loaded diagnose: the noise sockets in the table are kept unlinked */
	s = scan(&e, &ei, &o, 9u, keep, 1u);
	CK(s != NULL);
	if (s) {
		kgenome_diag_scan_drops(s, &d);
		EXPECT(d.refused == 4u && d.unlinked == 1u && d.nocap == 1u, "named: refused 4, unlinked 1, nocap 1 (%u %u %u)", d.refused, d.unlinked,
		       d.nocap);
		EXPECT(kgenome_diag_scan_count(s) == 7u, "named: 7 nodes kept (%u)", kgenome_diag_scan_count(s));
		the_links(s, &a, "named");
		kgenome_diag_scan_free(s);
	}
	/*
	 * THE RULE ITSELF, on a table built by hand (no route makes these two shapes): a node ON a link with NO capability is dropped (nocap),
	 * and a capability whose GROUP a diagnose names is kept unlinked (the matcher names groups: kof_diag_node.cap).
	 */
	{
		struct kgenome_diag_hit *h;
		uint32_t i0, i1, i2;
		uint16_t grp[1];
		const uint16_t member = KGENOME_NUCLEO_ALLOC_EXEC;

		grp[0] = kgenome_nucleo_cap_generic(member);
		CK(grp[0] != member);
		s = scan(&e, &ei, &o, 0, grp, 1u);         /* the program above, a roomy table: then three nodes added by hand */
		CK(s != NULL);
		if (s) {
			i0 = kgenome_diag_scan_count(s);
			CK(kgenome_diag_hit_add(s, 0x10, KGENOME_NUCLEO_NONE, 0) != NULL);         /* i0: no capability, a producer of a link */
			CK(kgenome_diag_hit_add(s, 0x20, KGENOME_NUCLEO_NET_CONNECT, 0) != NULL);  /* i1: its consumer */
			CK(kgenome_diag_hit_add(s, 0x30, member, 0) != NULL);                     /* i2: unlinked, its group named */
			i1 = i0 + 1u;
			i2 = i0 + 2u;
			CK(kgenome_diag_hit_add(s, 0x40, KGENOME_NUCLEO_NONE, 0) != NULL);         /* i0 + 3: no capability, the producer of i1's number */
			h = kgenome_diag_hit_of(s, i1);
			h->nr_from = (uint16_t)(i0 + 3u);
			CK(kgenome_diag_note_in_how(s, h, (uint16_t)i0, KGENOME_DIAG_ROLE_FD, KGENOME_DIAG_KIND_PRODUCED, KGENOME_DIAG_LINK_PROVEN) == 0);
			s->nodes_full = 1;
			kgenome_diag_nodes_keep(s);
			kgenome_diag_scan_drops(s, &d);
			/* AUD-6 (audit 2026-11-16): the row pinned "a linked node with no capability is dropped" and checked only the counts (c): the consumer's
			 * input then named 0xffff. Now the producer of a kept node's input is kept and the link names it. */
			EXPECT(node_at(s, 0x30, &x), "rule: a capability whose group a diagnose names is kept unlinked");
			EXPECT(node_at(s, 0x20, &x), "rule: the consumer with a capability on a link is kept");
			{
				uint32_t q, ok = 0;

				for (q = 0; node_at(s, 0x20, &x) && q < kgenome_diag_in_count(s, x); q++) {
					const struct kgenome_diag_in *in = kgenome_diag_in_at(s, x, q);

					if (in->role == KGENOME_DIAG_ROLE_FD && in->from < kgenome_diag_scan_count(s) && kgenome_diag_scan_at(s, in->from)->at == 0x10)
						ok = 1;
				}
				EXPECT(ok, "rule: the consumer's input names its producer (no-capability, kept with the link), not 0xffff");
				EXPECT(node_at(s, 0x20, &x) && kgenome_diag_scan_at(s, x)->nr_from < kgenome_diag_scan_count(s) &&
				       kgenome_diag_scan_at(s, kgenome_diag_scan_at(s, x)->nr_from)->at == 0x40, "rule: the number's producer is kept with it");
				EXPECT(d.nocap >= 1u, "rule: the unlinked capability-less node is still dropped (nocap %u)", d.nocap);
			}
			(void)i2;
			kgenome_diag_scan_free(s);
		}
	}
	printf("lineage_keep: %d failure(s)\n", hk_fails);
	return hk_fails != 0;
}
