/*
 * diag_form_nullargs - no memory function of the detection form is handed a NULL pointer, whatever the length (C99 7.1.4: memcpy(d, NULL, 0)
 * is undefined, and -fsanitize=undefined says so: "null pointer passed as argument 1, which is declared to never be null").
 *
 * memcpy, memmove, memcmp and memset are wrapped at link time (UNIT_LIBS_diag_form_nullargs, the way tests/unit/diag_text_nullargs.c counts
 * the TEXT route's) and every call that gets a NULL pointer is counted over what the form's readers are given that has NOTHING in it: a
 * record whose KDIG_SEC_FORM sections hold no bytes (before the real ones, after them, and alone), an empty stream, an empty text, a
 * form of one marker. Found by the fuzz of tests/unit/diag_form_engine.c under unit-asan: formacc_add (kofdiag.c) copied a section of
 * length zero into a buffer that did not exist yet. A run without a sanitiser never shows it (the copy of 0 bytes does nothing), which
 * is why the count is the test. RED, measured: with the guard of formacc_add removed the sanitised twin (unit-asan, UBSAN) fails this
 * row with "null pointer passed as argument 1"; the RELEASE build does not count it, because gcc expands that one copy inline (rep movsb)
 * and the link-time wrap never sees it. So the wrap catches a call the compiler leaves a call, and the sanitiser the rest.
 *
 * usage: diag_form_nullargs
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "../../libkofeng/databases/pack/diagform.h"
#include "../../libkofeng/databases/pack/dbcore.h"
#include "../../libkofeng/databases/diagsrc.h"
#include "../../libkofeng/detectors/linkage/kofdiag.h"

void *__real_memcpy(void *d, const void *s, size_t n);
void *__real_memmove(void *d, const void *s, size_t n);
int __real_memcmp(const void *a, const void *b, size_t n);
void *__real_memset(void *d, int c, size_t n);
void *__wrap_memcpy(void *d, const void *s, size_t n);
void *__wrap_memmove(void *d, const void *s, size_t n);
int __wrap_memcmp(const void *a, const void *b, size_t n);
void *__wrap_memset(void *d, int c, size_t n);

static unsigned armed, nulls;
static const char *where;

static void note(const char *fn, int which)
{
	if (armed && nulls++ < 6u)
		printf("  NULL pointer as argument %d of %s while reading [%s]\n", which, fn, where);
}

void *__wrap_memcpy(void *d, const void *s, size_t n)
{
	if (!d)
		note("memcpy", 1);
	if (!s)
		note("memcpy", 2);
	return __real_memcpy(d, s, n);
}

void *__wrap_memmove(void *d, const void *s, size_t n)
{
	if (!d)
		note("memmove", 1);
	if (!s)
		note("memmove", 2);
	return __real_memmove(d, s, n);
}

int __wrap_memcmp(const void *a, const void *b, size_t n)
{
	if (!a)
		note("memcmp", 1);
	if (!b)
		note("memcmp", 2);
	return __real_memcmp(a, b, n);
}

void *__wrap_memset(void *d, int c, size_t n)
{
	if (!d)
		note("memset", 1);
	return __real_memset(d, c, n);
}

static size_t record(uint8_t *out, const char *name, const uint8_t *sections, size_t sn)
{
	size_t at = 0, nl = strlen(name);

	out[at++] = 0;
	out[at++] = 0;
	out[at++] = 0;
	out[at++] = (uint8_t)nl;
	memcpy(out + at, name, nl);
	at += nl;
	out[at++] = 0;
	if (sn)
		memcpy(out + at, sections, sn);
	return at + sn;
}

int main(void)
{
	struct kof_form *f = kof_form_new();
	struct kof_form_match *m;
	uint8_t wire[512], sec[1024], rec[2048], all[1200];
	size_t wn, sn, rn;
	struct kof_diag_node node[KOF_DIAG_MAX_NODE];
	char name[64], needs[2100];
	struct kof_diag_store st = { node, name, needs, sizeof name, sizeof needs, KOF_DIAG_MAX_NODE };
	struct kof_diag d;
	int bad = 0;
	struct kof_dsrc *src = calloc(1, sizeof *src);
	struct kof_dsrc_view v;

	kof_form_add_str(f, KOF_STR_LITERAL, 0, (const uint8_t *)"abcd", 4u);
	m = &f->match[f->n_match++];
	memset(m, 0, sizeof *m);
	m->kind = KOF_FORM_M_FIND;
	m->rule = KOF_FORM_R_ANY;
	m->n = 1;
	m->mask = KOF_SCAN_ALL;
	f->node[0].op = KOF_FORM_OP_LEAF;
	f->n_node = 1;
	wn = kof_form_wire_write(f, wire);
	sn = kof_form_section_write(wire, wn, sec);

	armed = 1;
	/* a section of no bytes first, then the real ones, then another of none */
	where = "an empty FORM section before the real ones";
	all[0] = KDIG_SEC_FORM;
	all[1] = 0;
	memcpy(all + 2, sec, sn);
	rn = record(rec, "empty_first", all, 2u + sn);
	memset(&d, 0, sizeof d);
	bad += kof_diag_load(kof_buf_make(rec, rn), &d, &st) != 1 || !d.form;
	kof_diag_form_free(&d);
	where = "an empty FORM section after the real ones";
	memcpy(all, sec, sn);
	all[sn] = KDIG_SEC_FORM;
	all[sn + 1u] = 0;
	rn = record(rec, "empty_last", all, sn + 2u);
	memset(&d, 0, sizeof d);
	bad += kof_diag_load(kof_buf_make(rec, rn), &d, &st) != 1 || !d.form;
	kof_diag_form_free(&d);
	where = "a record whose only FORM section is empty (refused: no nodes and no form)";
	all[0] = KDIG_SEC_FORM;
	all[1] = 0;
	rn = record(rec, "only_empty", all, 2u);
	memset(&d, 0, sizeof d);
	bad += kof_diag_load(kof_buf_make(rec, rn), &d, &st) != 0;
	kof_diag_form_free(&d);
	where = "several empty FORM sections";
	{
		size_t k = 0, i;

		for (i = 0; i < 5u; i++) {
			all[k++] = KDIG_SEC_FORM;
			all[k++] = 0;
		}
		rn = record(rec, "many_empty", all, k);
		memset(&d, 0, sizeof d);
		bad += kof_diag_load(kof_buf_make(rec, rn), &d, &st) != 0;
		kof_diag_form_free(&d);
	}
	where = "an empty stream, a stream of one byte, and a form decoded from the wire";
	{
		struct kof_form *g = kof_form_decode(wire, 0, NULL), *h = kof_form_decode(wire, 1, NULL), *k = kof_form_decode(wire, wn, NULL);

		bad += g != NULL || h != NULL || k == NULL;
		kof_form_free(g);
		kof_form_free(h);
		kof_form_free(k);
	}
	where = "the source reader over empty and one-line texts";
	{
		static const char *const t[] = { "", "\n", "KOF_DIAG_NAME(t);\n",
			"KOF_DIAG_NAME(t);\nKOF_TARGET_RANGE(r, KOF_SCAN_ALL);\nKOF_DEFINE_HEXSTR(s0, \"\");\nKOF_DIAG_EXPR();\n",
			"KOF_DIAG_NAME(t);\nKOF_TARGET_RANGE(r, KOF_SCAN_ALL);\nKOF_DEFINE_STR(s0, \"a\", KOF_CASE_EXACT, KOF_WORD_SUBSTRING);\n"
			"KOF_DIAG_FIND(m0, KOF_FIND_ANY, r, s0);\nKOF_DIAG_EXPR(m0);\n" };
		size_t i;

		for (i = 0; i < sizeof t / sizeof t[0]; i++) {
			(void)kof_dsrc_parse(t[i], strlen(t[i]), src, NULL);
			memset(&v, 0, sizeof v);
			(void)kof_dsrc_resolve(src, &v, NULL);
			kof_dsrc_view_free(&v);
		}
	}
	armed = 0;
	free(src);
	kof_form_free(f);
	if (nulls || bad) {
		printf("diag_form_nullargs: %u call(s) with a NULL pointer, %d wrong answer(s)\n", nulls, bad);
		return 1;
	}
	printf("diag_form_nullargs: ok\n");
	return 0;
}
