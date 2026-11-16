/*
 * roles_pe - the row table seen through the PE route and the lineage stages, on a PE32+ written by hand (aptgap_pe.h: no sample byte).
 *
 * RED ON THE OLD CODE:
 *   lg5_ws2_by_ordinal    socket -> connect with WS2_32 imported BY ORDINAL (23, 4): gather_imports (diag_pe.c) skipped an import with no
 *                         name, so neither call was a node. CONTROL lg5 by name: the same code with the names links. (From fix_aptgap,
 *                         merged with its fix.) Why missed: (b) lineage_import builds every PE import by name.
 *   d1_closesocket_link   socket -> closesocket(s) -> connect(closesocket's result): the old hand-on made closesocket's status a SOCKET, so
 *                         connect's descriptor was linked to the close. The row says closesocket ends its argument and returns a status.
 *                         CONTROL: connect(socket's result) links to the socket. Why missed: (b) no fixture called a call that ends an object.
 *                         AND (fix_linrow) closesocket's own input, socket's result: the row's fd0 (its capability NET_OPEN names no
 *                         input), read by lineage only when it asks the node's row and not its capability. By name, and BY ORDINAL
 *                         (WS2_32 #23, #3, #4), where the import has no name in the file and only the row the node carries
 *                         (kgenome_diag_hit.row) says which argument is the socket. Why missed: (c) the CONTROL checked connect's
 *                         link only, and (b) no ordinal fixture called a call whose row differs from its capability.
 *   ordinal_other_dll     an ordinal of a library whose ordinals are not fixed (KERNEL32 #23) stays no node: nothing is guessed.
 *   wsock32_differs       wsock32's ordinal 10 is inet_addr (a net-addr node) where ws2_32's 10 is ioctlsocket (no word): the two tables are two.
 */
#include <kgenome.h>
#include <genotype/image/pe_image.h>
#include <phenotype/diag_private.h>
#include <phenotype/diag_lineage.h>
#include <stdlib.h>

#include "aptgap_pe.h"

static int fails;
#define CK(c) do { if (!(c)) { printf("  FAIL %s:%d  %s\n", __FILE__, __LINE__, #c); fails++; } } while (0)

struct scan {
	struct kgenome_pe_info pi;
	struct kgenome_obj obj;
	struct kgenome_diag_scan *s;
};

static int scan_pe(struct scan *r, struct ap_pe *p)
{
	struct kgenome_diag_inputs in;

	memset(r, 0, sizeof *r);
	/* the .pdata row an x64 compiler writes for the function the row builds at 0x1000 (it calls, so it has one): since 2026-11-16 the function table is
	 * made from metadata only, and an image that declares no function is one unpartitioned unit the static lineage does not solve */
	if (!p->nrf && p->pc > 0x1000u)
		ap_rf(p, 0x1000u, p->pc, ap_unwind(p, 0, 0, 0, 0));
	if (!kgenome_pe_image_parse(kof_buf_make(p->b, p->n), &r->pi, &r->obj))
		return 0;
	r->obj.file_header = &r->pi;
	r->obj.obj_size = p->n;
	memset(&in, 0, sizeof in);
	r->s = kgenome_diag_scan_with_inputs(&r->obj, p->b, p->n, KGENOME_DIAG_RUN_SYMBOL | KGENOME_DIAG_RUN_LINEAGE, &in);
	return r->s != NULL;
}

/* the node on the instruction at rva `at` (-1: none) */
static int node_at(const struct scan *r, uint32_t at, uint16_t *cap)
{
	uint32_t i, n = r->s ? kgenome_diag_scan_count(r->s) : 0u;

	for (i = 0; i < n; i++) {
		const struct kgenome_diag_hit *h = kgenome_diag_scan_at(r->s, i);

		if (h->at == ap_off(at) && h->cap != KGENOME_NUCLEO_NONE && !(h->bits & KGENOME_DIAG_H_SUPERSEDED)) {
			if (cap)
				*cap = h->cap;
			return (int)i;
		}
	}
	return -1;
}

/* is there a PRODUCED input of the node at `cat` from the node at `pat`? */
static int linked(const struct scan *r, uint32_t cat, uint32_t pat)
{
	int c = node_at(r, cat, NULL), p = node_at(r, pat, NULL);
	uint32_t k;

	if (c < 0 || p < 0)
		return 0;
	for (k = 0; k < kgenome_diag_in_count(r->s, (uint32_t)c); k++) {
		const struct kgenome_diag_in *x = kgenome_diag_in_at(r->s, (uint32_t)c, k);

		if (x && x->from == (uint16_t)p && x->kind == KGENOME_DIAG_KIND_PRODUCED)
			return 1;
	}
	return 0;
}

static void done(struct scan *r, struct ap_pe *p)
{
	if (r->s)
		kgenome_diag_scan_free(r->s);
	free(p);
}

static void lg5_ws2(int by_name)
{
	struct ap_pe *p = calloc(1, sizeof *p);
	struct scan r;
	uint32_t s_so, s_co, so, co;

	ap_init(p);
	s_so = ap_import(p, "WS2_32.dll", by_name ? "socket" : NULL, 23);
	s_co = ap_import(p, "WS2_32.dll", by_name ? "connect" : NULL, 4);
	ap_imports_done(p);
	ap_org(p, 0x1000);
	ap_hex(p, "53 48 83 ec 30");                    /* push rbx; sub rsp,0x30 */
	ap_hex(p, "b9 02 00 00 00 ba 01 00 00 00 41 b8 06 00 00 00");   /* AF_INET, SOCK_STREAM, IPPROTO_TCP */
	so = ap_call_iat(p, s_so);
	ap_hex(p, "48 89 c3 48 89 d9 48 8d 54 24 20 41 b8 10 00 00 00"); /* mov rbx,rax; mov rcx,rbx; lea rdx,[rsp+0x20]; mov r8d,16 */
	co = ap_call_iat(p, s_co);
	ap_hex(p, "48 83 c4 30 5b c3");
	CK(scan_pe(&r, p));
	if (node_at(&r, so, NULL) < 0)
		printf("  lg5 (%s): no node on `call [socket]`\n", by_name ? "by name" : "by ordinal 23");
	CK(node_at(&r, so, NULL) >= 0 && node_at(&r, co, NULL) >= 0);
	CK(linked(&r, co, so));
	done(&r, p);
}

/* socket; closesocket(s); connect(<closesocket's result>, ...) - and the CONTROL connect(<socket's result>); by name or by ordinal */
static void d1_closesocket_link(int control, int by_ordinal)
{
	struct ap_pe *p = calloc(1, sizeof *p);
	struct scan r;
	uint32_t s_so, s_cl, s_co, so, cl, co;

	ap_init(p);
	s_so = ap_import(p, "WS2_32.dll", by_ordinal ? NULL : "socket", 23);
	s_cl = ap_import(p, "WS2_32.dll", by_ordinal ? NULL : "closesocket", 3);
	s_co = ap_import(p, "WS2_32.dll", by_ordinal ? NULL : "connect", 4);
	ap_imports_done(p);
	ap_org(p, 0x1000);
	ap_hex(p, "53 48 83 ec 30");
	ap_hex(p, "b9 02 00 00 00 ba 01 00 00 00 41 b8 06 00 00 00");
	so = ap_call_iat(p, s_so);
	ap_hex(p, "48 89 c3 48 89 d9");                 /* mov rbx,rax; mov rcx,rbx */
	cl = ap_call_iat(p, s_cl);
	if (control)
		ap_hex(p, "48 89 d9");                  /* mov rcx,rbx   (the socket) */
	else
		ap_hex(p, "48 89 c1");                  /* mov rcx,rax   (closesocket's result) */
	ap_hex(p, "48 8d 54 24 20 41 b8 10 00 00 00");
	co = ap_call_iat(p, s_co);
	ap_hex(p, "48 83 c4 30 5b c3");
	CK(scan_pe(&r, p));
	CK(node_at(&r, so, NULL) >= 0 && node_at(&r, cl, NULL) >= 0 && node_at(&r, co, NULL) >= 0);
	if (control) {
		/* closesocket's own input: fd0 of its row (NET_OPEN, its capability, names none) */
		CK(linked(&r, co, so));
		if (!linked(&r, cl, so))
			printf("  d1 (%s): closesocket's socket is not linked to socket's result\n", by_ordinal ? "by ordinal" : "by name");
		CK(linked(&r, cl, so));
	} else {
		if (linked(&r, co, cl))
			printf("  d1: connect's descriptor linked to closesocket's status\n");
		CK(!linked(&r, co, cl));
		CK(!linked(&r, co, so));
	}
	done(&r, p);
}

static void ordinal_other_dll(void)
{
	struct ap_pe *p = calloc(1, sizeof *p);
	struct scan r;
	uint32_t s_x, x;

	ap_init(p);
	s_x = ap_import(p, "KERNEL32.dll", NULL, 23);
	ap_imports_done(p);
	ap_org(p, 0x1000);
	ap_hex(p, "48 83 ec 28");
	x = ap_call_iat(p, s_x);
	ap_hex(p, "48 83 c4 28 c3");
	CK(scan_pe(&r, p));
	CK(node_at(&r, x, NULL) < 0);
	done(&r, p);
}

static void wsock32_differs(void)
{
	struct ap_pe *p = calloc(1, sizeof *p);
	struct scan r;
	uint32_t s_a, s_b, a, b;
	uint16_t cap = 0;

	ap_init(p);
	s_a = ap_import(p, "WSOCK32.dll", NULL, 10);   /* inet_addr */
	s_b = ap_import(p, "WS2_32.dll", NULL, 10);    /* ioctlsocket: no word */
	ap_imports_done(p);
	ap_org(p, 0x1000);
	ap_hex(p, "48 83 ec 28");
	a = ap_call_iat(p, s_a);
	b = ap_call_iat(p, s_b);
	ap_hex(p, "48 83 c4 28 c3");
	CK(scan_pe(&r, p));
	CK(node_at(&r, a, &cap) >= 0 && cap == KGENOME_NUCLEO_NET_ADDR);
	CK(node_at(&r, b, NULL) < 0);
	done(&r, p);
}

int main(void)
{
	lg5_ws2(1);             /* CONTROL */
	lg5_ws2(0);
	d1_closesocket_link(1, 0); /* CONTROL */
	d1_closesocket_link(0, 0);
	d1_closesocket_link(1, 1); /* CONTROL, by ordinal */
	d1_closesocket_link(0, 1);
	ordinal_other_dll();
	wsock32_differs();
	printf("roles_pe: %d failure(s)\n", fails);
	return fails != 0;
}
