/*
 * aptgap_lineage - the relationships a researcher reads in an x64 MSVC loader/backdoor DLL (the 2026-11-15 APT set), each written as a minimal
 * PE32+ by hand (aptgap_pe.h: no sample byte), scanned with the symbol route and the lineage stages the plan gives a PE, and held to the link
 * the code has. A CONTROL beside a case changes only the variable under test. The rows here are the ones fix_linrow made green (the lineage
 * reads the ROLE OF AN ARGUMENT from the node's row, kgenome_diag_hit.row, and the PE plan runs LOCS); the other rows of fix_aptgap
 * (lg3 indirect call, lg4 out-pointer, lg7 decoded path, lg10 alloc written by the code) wait for their own fix, lg5 is in roles_pe.c, and
 * lg8 (a chained .pdata part) passes on main since the PF-1 fix.
 *
 *   lg1_lib_load_to_resolve        LoadLibraryA -> GetProcAddress (the module handle through a frame spill, one function). Sink: the stage
 *                                  asked the role by CAPABILITY (kgenome_diag_role_of_arg), and RESOLVE's capability names no input; the
 *                                  row of GetProcAddress names fd0 (the module) and path1.
 *   lg2_resolve_to_thread_start    GetProcAddress -> CreateThread (the resolved pointer is the start routine). Sink: the same; the row of
 *                                  CreateThread names tgt2 (lpStartAddress) and val3.
 *   lg6_global_handle              CreateFileA -> global -> WriteFile in ONE function, an import call between the store and the load. Sink:
 *                                  the plan row for PE (kgenome_diag_lineage_plan, diag_class.c) had no LOCS stage. CONTROL: a stack slot.
 *   lg9_exec                       HeapAlloc -> CreateProcessA's COMMAND LINE (argument 1; argument 0 is NULL). Sink: the role by capability
 *                                  (EXEC_IMAGE: index 0 is PATH) read rcx (a constant NULL) and never rdx. CONTROL lg9_exec(1): WinExec(buf),
 *                                  whose command line is argument 0.
 *
 * Why the old tests missed these: (a) the vocabulary the generated programs use (lineage_ir.h) holds no LIB_OPEN, RESOLVE or THREAD call;
 * (b) no PE fixture had a global handle with the PE plan, nor a call whose row puts an input elsewhere than its capability does.
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
	memset(&in, 0, sizeof in);              /* the plan's stages: what a scan of a PE runs */
	r->s = kgenome_diag_scan_with_inputs(&r->obj, p->b, p->n, KGENOME_DIAG_RUN_SYMBOL | KGENOME_DIAG_RUN_LINEAGE, &in);
	return r->s != NULL;
}

/* the node on the instruction at rva `at` (-1: none) */
static int node_at(const struct scan *r, uint32_t at)
{
	uint32_t i, n = kgenome_diag_scan_count(r->s);

	for (i = 0; i < n; i++) {
		const struct kgenome_diag_hit *h = kgenome_diag_scan_at(r->s, i);

		if (h->at == ap_off(at) && h->cap != KGENOME_NUCLEO_NONE && !(h->bits & KGENOME_DIAG_H_SUPERSEDED))
			return (int)i;
	}
	return -1;
}

/* is there a PRODUCED input of the node at `cat` from the node at `pat` (any role, any strength)? */
static int linked(const struct scan *r, uint32_t cat, uint32_t pat, const char *what)
{
	int c = node_at(r, cat), p = node_at(r, pat);
	uint32_t k;

	if (c < 0 || p < 0) {
		printf("  %s: no node at %s 0x%x\n", what, c < 0 ? "consumer" : "producer", c < 0 ? cat : pat);
		return 0;
	}
	for (k = 0; k < kgenome_diag_in_count(r->s, (uint32_t)c); k++) {
		const struct kgenome_diag_in *x = kgenome_diag_in_at(r->s, (uint32_t)c, k);

		if (x && x->from == (uint16_t)p && x->kind == KGENOME_DIAG_KIND_PRODUCED)
			return 1;
	}
	printf("  %s: node 0x%x (%s) has %u input(s), none from 0x%x (%s)\n", what, cat, kgenome_nucleo_cap_name(kgenome_diag_scan_at(r->s, (uint32_t)c)->cap),
	       kgenome_diag_in_count(r->s, (uint32_t)c), pat, kgenome_nucleo_cap_name(kgenome_diag_scan_at(r->s, (uint32_t)p)->cap));
	return 0;
}

static void done(struct scan *r, struct ap_pe *p)
{
	kgenome_diag_scan_free(r->s);
	free(p);
}

/* ---- LoadLibraryA -> GetProcAddress -> CreateThread / call ---- */

struct loader { uint32_t ll, gpa, ct, icall; };

static void loader_image(struct ap_pe *p, struct loader *x)
{
	uint32_t s_ll, s_gpa, s_ct, dll, fn;

	ap_init(p);
	s_ll = ap_import(p, "KERNEL32.dll", "LoadLibraryA", 0);
	s_gpa = ap_import(p, "KERNEL32.dll", "GetProcAddress", 0);
	s_ct = ap_import(p, "KERNEL32.dll", "CreateThread", 0);
	ap_imports_done(p);
	dll = ap_str(p, "C:\\x\\w.dll");
	fn = ap_str(p, "Initializing");
	ap_org(p, 0x1000);
	ap_hex(p, "48 83 ec 48");                       /* sub rsp,0x48 */
	ap_rip(p, "48 8d 0d", dll);                     /* lea rcx,[rip+dll] */
	x->ll = ap_call_iat(p, s_ll);
	ap_hex(p, "48 89 44 24 30");                    /* mov [rsp+0x30],rax   (the module, spilled as MSVC /Od does) */
	ap_rip(p, "48 8d 15", fn);                      /* lea rdx,[rip+fn] */
	ap_hex(p, "48 8b 4c 24 30");                    /* mov rcx,[rsp+0x30] */
	x->gpa = ap_call_iat(p, s_gpa);
	ap_hex(p, "48 89 44 24 38");                    /* mov [rsp+0x38],rax   (the resolved pointer) */
	ap_hex(p, "31 c9 31 d2");                       /* xor ecx,ecx; xor edx,edx */
	ap_hex(p, "4c 8b 44 24 38");                    /* mov r8,[rsp+0x38]    lpStartAddress */
	ap_hex(p, "45 31 c9");                          /* xor r9d,r9d */
	ap_hex(p, "c7 44 24 20 00 00 00 00");           /* dwCreationFlags */
	ap_hex(p, "48 c7 44 24 28 00 00 00 00");        /* lpThreadId */
	x->ct = ap_call_iat(p, s_ct);
	x->icall = ap_hex(p, "ff 54 24 38");            /* call [rsp+0x38]      the resolved pointer, called */
	ap_hex(p, "48 83 c4 48 c3");
}

static void lg1_lib_load_to_resolve(void)
{
	struct ap_pe *p = calloc(1, sizeof *p);
	struct scan r;
	struct loader x;

	loader_image(p, &x);
	CK(scan_pe(&r, p));
	CK(node_at(&r, x.ll) >= 0 && node_at(&r, x.gpa) >= 0);     /* the nodes exist on main: the gap is the link */
	CK(linked(&r, x.gpa, x.ll, "lg1 module handle"));
	done(&r, p);
}

static void lg2_resolve_to_thread_start(void)
{
	struct ap_pe *p = calloc(1, sizeof *p);
	struct scan r;
	struct loader x;

	loader_image(p, &x);
	CK(scan_pe(&r, p));
	CK(node_at(&r, x.ct) >= 0);
	CK(linked(&r, x.ct, x.gpa, "lg2 thread start routine"));
	done(&r, p);
}

/* ---- a handle kept in a global ---- */

static void lg6_global(int stack)
{
	struct ap_pe *p = calloc(1, sizeof *p);
	struct scan r;
	uint32_t s_cf, s_wf, s_sl, path, cf, wf;
	const uint32_t g = AP_DATA + 0x10u;

	ap_init(p);
	s_cf = ap_import(p, "KERNEL32.dll", "CreateFileA", 0);
	s_wf = ap_import(p, "KERNEL32.dll", "WriteFile", 0);
	s_sl = ap_import(p, "KERNEL32.dll", "Sleep", 0);
	ap_imports_done(p);
	path = ap_str(p, "C:\\x\\log.dat");
	ap_org(p, 0x1000);
	ap_hex(p, "48 83 ec 48");
	ap_rip(p, "48 8d 0d", path);
	ap_hex(p, "ba 00 00 00 40 45 31 c0 45 31 c9");
	ap_hex(p, "c7 44 24 20 02 00 00 00 c7 44 24 28 80 00 00 00 48 c7 44 24 30 00 00 00 00");
	cf = ap_call_iat(p, s_cf);
	if (stack)
		ap_hex(p, "48 89 44 24 38 90 90");      /* mov [rsp+0x38],rax */
	else
		ap_rip(p, "48 89 05", g);               /* mov [rip+g],rax */
	ap_hex(p, "b9 0a 00 00 00");                    /* mov ecx,10 */
	ap_call_iat(p, s_sl);                           /* Sleep(10): rax and rcx are the callee's now */
	if (stack)
		ap_hex(p, "48 8b 4c 24 38 90 90");
	else
		ap_rip(p, "48 8b 0d", g);               /* mov rcx,[rip+g] */
	ap_hex(p, "31 d2 45 31 c0 45 31 c9 48 c7 44 24 20 00 00 00 00");
	wf = ap_call_iat(p, s_wf);
	ap_hex(p, "48 83 c4 48 c3");
	CK(scan_pe(&r, p));
	CK(linked(&r, wf, cf, stack ? "lg6 CONTROL handle in a stack slot" : "lg6 handle in a global"));
	done(&r, p);
}

/* ---- CreateProcessA's command line is its SECOND argument ---- */

static void lg9_exec(int winexec)
{
	struct ap_pe *p = calloc(1, sizeof *p);
	struct scan r;
	uint32_t s_ha, s_ex, ha, ex;

	ap_init(p);
	s_ha = ap_import(p, "KERNEL32.dll", "HeapAlloc", 0);
	s_ex = ap_import(p, "KERNEL32.dll", winexec ? "WinExec" : "CreateProcessA", 0);
	ap_imports_done(p);
	ap_org(p, 0x1000);
	ap_hex(p, "53 48 81 ec 90 00 00 00");           /* push rbx; sub rsp,0x90 */
	ap_hex(p, "31 c9 31 d2 41 b8 00 10 00 00");     /* HeapAlloc(0, 0, 0x1000): the heap handle is no part of the case */
	ha = ap_call_iat(p, s_ha);
	ap_hex(p, "48 89 c3");                          /* mov rbx,rax: the command line buffer */
	if (winexec) {
		ap_hex(p, "48 89 d9 ba 00 00 00 00");    /* WinExec(buf, SW_HIDE) */
	} else {
		/* CreateProcessA(NULL, buf, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi) */
		ap_hex(p, "31 c9 48 89 da 45 31 c0 45 31 c9");
		ap_hex(p, "c7 44 24 20 00 00 00 00 c7 44 24 28 00 00 00 08 48 c7 44 24 30 00 00 00 00 48 c7 44 24 38 00 00 00 00");
		ap_hex(p, "48 8d 44 24 60 48 89 44 24 40 48 8d 44 24 50 48 89 44 24 48");
	}
	ex = ap_call_iat(p, s_ex);
	ap_hex(p, "48 81 c4 90 00 00 00 5b c3");
	CK(scan_pe(&r, p));
	CK(node_at(&r, ha) >= 0 && node_at(&r, ex) >= 0);
	CK(linked(&r, ex, ha, winexec ? "lg9 CONTROL WinExec(buf)" : "lg9 CreateProcessA(NULL, buf)"));
	done(&r, p);
}

int main(void)
{
	lg1_lib_load_to_resolve();
	lg2_resolve_to_thread_start();
	lg6_global(1);          /* CONTROL */
	lg6_global(0);
	lg9_exec(1);            /* CONTROL */
	lg9_exec(0);
	printf("aptgap_lineage: %d failure(s)\n", fails);
	return fails != 0;
}
