/*
 * parse_once - the structure of an object is READ once per object, and a view of it is not
 * a second object to read: the header parse, the import walk, the library-span search, the
 * normaliser's walk of the bytes, and the engine's pattern sweep (how many times the object's
 * BYTES are gone over) are counted for every shape of object and held to their number.
 *
 * prod_once counts the products the engine builds through its latches (symbols, functions,
 * the decode walk, relocations, imports, API hashes, the diagnose graph). This counts what it
 * cannot see from there: the lib entry points the parsers are reached through and the byte
 * passes, by wrapping them at link time (UNIT_LIBS_parse_once in mk/tests.mk: --wrap), so the
 * production code carries no counter for it.
 *
 * WHAT IS HELD TO, per scanned object tree (the root, and the views and children it made):
 *   - kgenome_elf_image_parse / kgenome_pe_image_parse: once for the root and never for its
 *     normalised view - "the view's header is never parsed" (CLAUDE.md, derived objects);
 *   - kgenome_pe_imports: at most once; kgenome_true_find_object: at most once;
 *   - kof_exe_norm_masked: at most once - one view per object, and not for the view;
 *   - the engine's pattern sweep (kofpix_sweep): the bytes it walked, over the tree, are
 *     at most one pass over every object in it - a region is swept once, not once per mask.
 *
 *   - the normaliser's decode (kof_exe_decode_ex) and its read-only probe
 *     (kof_exe_decode_would_change): at most once per object, and the view is not decoded again;
 *   - the script identify: every identification of a script is ONE scan of its bytes for a tag. The
 *     sniff and the parse used to find the tag twice over the same bytes; the engine now asks
 *     kof_script_sniff_keep and hands what it found to kof_script_parse_keep, so the plain
 *     kof_script_sniff is never called by a scan, and the scans counted (a sniff that searched, a
 *     parse that had to, a declared view's plain parse) are the number of parses.
 *
 * NAMED, NOT HELD: the ELF symbol table (kgenome_elf_symtab_of) is opened by four consumers
 * that extract different things (trueline, the symbol block, the declared symbols, the
 * relocation table); it is printed so a fifth shows. Measured cost below 0.01 % of the scan.
 */
#include "caps_fix.h"
#include "caps_e2e.h"
#include "caps_pe_fix.h"
#include "../../libkofeng/scanners/scan.h"
#include "../../libkofeng/detectors/pattern/kofpix.h"
#include <genotype/image/elf_image.h>
#include <genotype/image/pe_image.h>
#include <celllysis/trueline.h>
#include "../../libkofeng/analyzers/normalize/executables.h"
#include "../../libkofeng/analyzers/parsers/scripts/script_parse.h"

static unsigned n_elf_parse, n_pe_parse, n_pe_imports, n_true, n_norm, n_symtab;
static unsigned n_decode, n_would, n_sniff_plain, n_sniff_keep, n_parse_keep, n_parse_plain, n_tag_scans;
static uint64_t swept;

int __real_kgenome_elf_image_parse(kof_buf file, struct kgenome_elf_info *info, struct kgenome_obj *obj);
int __wrap_kgenome_elf_image_parse(kof_buf file, struct kgenome_elf_info *info, struct kgenome_obj *obj)
{
	n_elf_parse++;
	return __real_kgenome_elf_image_parse(file, info, obj);
}

int __real_kgenome_pe_image_parse(kof_buf file, struct kgenome_pe_info *info, struct kgenome_obj *obj);
int __wrap_kgenome_pe_image_parse(kof_buf file, struct kgenome_pe_info *info, struct kgenome_obj *obj)
{
	n_pe_parse++;
	return __real_kgenome_pe_image_parse(file, info, obj);
}

void __real_kgenome_true_find_object(kof_buf file, const struct kgenome_elf_info *e, struct kgenome_true_all *out);
void __wrap_kgenome_true_find_object(kof_buf file, const struct kgenome_elf_info *e, struct kgenome_true_all *out)
{
	n_true++;
	__real_kgenome_true_find_object(file, e, out);
}

uint64_t __real_kof_exe_norm_masked(const struct kof_exe_norm_req *rq, struct kof_exe_norm_res *res);
uint64_t __wrap_kof_exe_norm_masked(const struct kof_exe_norm_req *rq, struct kof_exe_norm_res *res)
{
	n_norm++;
	return __real_kof_exe_norm_masked(rq, res);
}

int __real_kgenome_elf_symtab_of(kof_buf f, const struct kgenome_elf_info *p, struct kgenome_elf_symtab *out);
int __wrap_kgenome_elf_symtab_of(kof_buf f, const struct kgenome_elf_info *p, struct kgenome_elf_symtab *out)
{
	n_symtab++;
	return __real_kgenome_elf_symtab_of(f, p, out);
}

uint64_t __real_kofpix_sweep(const struct kofpix_set *set, struct kofpix_ctx *c, uint32_t bit,
			     struct kof_match_ctx *m, const struct kof_range *ext, uint32_t n_ext);
uint64_t __wrap_kofpix_sweep(const struct kofpix_set *set, struct kofpix_ctx *c, uint32_t bit,
			     struct kof_match_ctx *m, const struct kof_range *ext, uint32_t n_ext)
{
	uint64_t w = __real_kofpix_sweep(set, c, bit, m, ext, n_ext);

	swept += w;
	return w;
}

/* Prototypes of the wrappers added with the decode and script counters (the older ones above
 * have none), so the build stays free of -Wmissing-prototypes for what this adds. */
int __wrap_kof_exe_decode_ex(uint8_t *p, uint64_t n, struct kof_exe_decode_res *res);
int __wrap_kof_exe_decode_would_change(const uint8_t *p, uint64_t n);
int __wrap_kof_script_sniff(kof_buf file);
int __wrap_kof_script_sniff_keep(kof_buf file, void *keep);
int __wrap_kof_script_parse_keep(kof_buf file, struct kof_script_info *info, struct kof_obj_ctx *ctx,
				 const void *keep);
int __wrap_kof_script_parse(kof_buf file, struct kof_script_info *info, struct kof_obj_ctx *ctx);

int __real_kof_exe_decode_ex(uint8_t *p, uint64_t n, struct kof_exe_decode_res *res);
int __wrap_kof_exe_decode_ex(uint8_t *p, uint64_t n, struct kof_exe_decode_res *res)
{
	n_decode++;
	return __real_kof_exe_decode_ex(p, n, res);
}

int __real_kof_exe_decode_would_change(const uint8_t *p, uint64_t n);
int __wrap_kof_exe_decode_would_change(const uint8_t *p, uint64_t n)
{
	n_would++;
	return __real_kof_exe_decode_would_change(p, n);
}

int __real_kof_script_sniff(kof_buf file);
int __wrap_kof_script_sniff(kof_buf file)
{
	n_sniff_plain++;
	return __real_kof_script_sniff(file);
}

int __real_kof_script_sniff_keep(kof_buf file, void *keep);
int __wrap_kof_script_sniff_keep(kof_buf file, void *keep)
{
	int r = __real_kof_script_sniff_keep(file, keep);

	n_sniff_keep++;
	n_tag_scans += ((const struct kof_script_found *)keep)->have_tag != 0;   /* it searched for the tag */
	return r;
}

int __real_kof_script_parse_keep(kof_buf file, struct kof_script_info *info, struct kof_obj_ctx *ctx,
				 const void *keep);
int __wrap_kof_script_parse_keep(kof_buf file, struct kof_script_info *info, struct kof_obj_ctx *ctx,
				 const void *keep)
{
	n_parse_keep++;
	n_tag_scans += ((const struct kof_script_found *)keep)->have_tag == 0;   /* it has to (a shebang) */
	return __real_kof_script_parse_keep(file, info, ctx, keep);
}

int __real_kof_script_parse(kof_buf file, struct kof_script_info *info, struct kof_obj_ctx *ctx);
int __wrap_kof_script_parse(kof_buf file, struct kof_script_info *info, struct kof_obj_ctx *ctx)
{
	n_parse_plain++;
	n_tag_scans++;                  /* the plain parse always searches */
	return __real_kof_script_parse(file, info, ctx);
}

static uint8_t img[1u << 21];
static uint8_t code[1u << 20];

static void scan_it(const char *what, const uint8_t *b, uint64_t len, int pe)
{
	kof_scanner *sc = kscan_new(e2e_eng);
	struct kof_scan_option opt;
	struct e2e r;
	int i;

	CK(sc != NULL);
	if (!sc)
		return;
	memset(&opt, 0, sizeof opt);
	opt.max_produced_bytes = 64u << 20;
	opt.max_resident_bytes = 256u << 20;
	opt.max_object_bytes = 64u << 20;
	for (i = 0; i < 2; i++) {       /* twice on ONE scanner: nothing may leak into the next object */
		n_elf_parse = n_pe_parse = n_pe_imports = n_true = n_norm = n_symtab = 0;
		n_decode = n_would = n_sniff_plain = n_sniff_keep = n_parse_keep = n_parse_plain = n_tag_scans = 0;
		swept = 0;
		memset(&r, 0, sizeof r);
		(void)kscan_bytes(sc, b, len, what, &opt, e2e_on_object, &r);
		CK(r.n > 0);
		printf("  %-34s objects=%u elf_parse=%u pe_parse=%u true_find=%u norm=%u swept=%.2fx symtab_reads=%u\n",
		       what, r.n, n_elf_parse, n_pe_parse, n_true, n_norm, (double)swept / (double)len, n_symtab);
		CK(n_elf_parse + n_pe_parse <= 1u);
		if (pe < 0)                         /* a script: no image, and its identify counts below */
			CK(n_elf_parse + n_pe_parse == 0u && n_parse_keep + n_parse_plain >= 1u);
		CK(pe < 0 || (pe ? n_elf_parse == 0 : n_pe_parse == 0));
		CK(n_true <= 1u);
		if (pe < 0)
			printf("  %-34s identify: sniff_keep=%u parse_keep=%u parse_plain=%u tag_scans=%u\n", "",
			       n_sniff_keep, n_parse_keep, n_parse_plain, n_tag_scans);
		CK(n_norm <= 1u);
		CK(n_decode <= 1u && n_would <= 1u);
		CK(n_sniff_plain == 0u);                    /* a scan asks the pair that keeps what it found */
		CK(n_tag_scans == n_parse_keep + n_parse_plain);   /* one scan of the tag per identification */
		CK(swept <= (uint64_t)r.n * len);
	}
	kscan_free(sc);
}

/* Bytes a view is made from: a long run of zeroes and a long run of UTF-16 text, past the image. */
static uint64_t add_overlay(uint8_t *b, uint64_t len)
{
	unsigned i;

	memset(b + len, 0, 3000);
	len += 3000;
	for (i = 0; i < 400; i++) {
		b[len++] = (uint8_t)('a' + i % 26u);
		b[len++] = 0;
	}
	return len;
}

/* The shapes of tests/unit/api_engine_scripts.c, and a script that carries an encoded payload (a view). */
static void scan_scripts(void)
{
	static const char *pg[] = {
		"<html>\n<?php echo 1; ?>\n<p>x</p>\n<?php if(1){ ?>a<?php } ?></html>",
		"<?php\necho 1;\n?>\n",
		"<%@ Language=VBScript %>\n<% Response.Write 1 %>\n<html></html>",
		"<%@ page import=\"java.io.*\" %>\n<% out.println(1); %>",
		"<cfexecute name=\"x\"></cfexecute>\n<cfif a>b</cfif>\n<!--- c --->",
		"<html><script language=\"vbscript\">MsgBox 1</script></html>",
		"#!/bin/sh\nls\n",
		"#!/usr/bin/env python3\nprint(1)\n",
		"#!/bin/sh\necho 'ZWNobyBoZWxsbyB3b3JsZDsgY2htb2QgNzc3IC90bXAveA==' | base64 -d | sh\n",
		"<?php eval(base64_decode('ZWNobyAxOw==')); echo urldecode('%77%67%65%74%20%68%74%74%70'); ?>",
	};
	unsigned i;

	for (i = 0; i < sizeof pg / sizeof pg[0]; i++) {
		char what[48];
		size_t n = strlen(pg[i]);

		memcpy(img, pg[i], n);
		snprintf(what, sizeof what, "script page %u", i);
		scan_it(what, img, n, -1);
		CK(n_sniff_keep + n_parse_plain >= 1u);         /* it was identified at all */
	}
}

int main(void)
{
	unsigned n;
	uint64_t len;

	if (!e2e_open(NULL)) {
		printf("parse_once: no test database\n");
		return 1;
	}
	n = cf_stager64(code, 0);
	len = cf_elf64(img, sizeof img, code, n);
	scan_it("elf64 stager, no sections", img, len, 0);
	len = cf_add_sections(img, len, 1, 0x78, n, 0x400078, 1);
	scan_it("elf64 stager, with symbols", img, len, 0);
	len = cf_add_sections(img, len, 1, 0x78, n, 0x400078, 0);
	scan_it("elf64 stripped, section table", img, len, 0);
	n = cf_stager64(code, 0);
	len = cf_elf64(img, sizeof img, code, n);
	len = add_overlay(img, len);
	scan_it("elf64 with an overlay", img, len, 0);
	len = cf_elf32(img, sizeof img, code, n);
	scan_it("elf32", img, len, 0);
	len = cf_kmod(img, sizeof img, 4, 0);
	scan_it("relocatable object (kmod shape)", img, len, 0);
	n = pe32_stager(code, 0);
	len = pe_code(img, sizeof img, code, n, 0);
	scan_it("pe32 stager", img, len, 1);
	n = pe64_stager(code, 0);
	len = pe_code(img, sizeof img, code, n, 1);
	scan_it("pe64 stager", img, len, 1);
	len = add_overlay(img, len);
	scan_it("pe64 with an overlay (a view)", img, len, 1);
	scan_scripts();
	printf("parse_once: %s\n", fails ? "FAILED" : "ok");
	return fails != 0;
}
