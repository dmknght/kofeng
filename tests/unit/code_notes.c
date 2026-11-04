/*
 * code_notes - the engine's naming of what the lib read in the code (kof_codenotes_build): labels, comments, xrefs, syscalls.
 *
 * A raw 32-bit blob written by hand, the shape of a stager: a counted loop, `call $+5; pop`, and an `int 0x80` execve. Every note the analysis makes
 * is compared with the text a person would write for it, and the things it must NOT say are checked as hard as the things it must: a jump label is
 * never a function name, a backward jump is not called a loop, a number no register held is not named, and a blob's syscall carries the word that
 * says whose table the name is from. The same blob read as 64-bit, and with no code at all, are answers and not crashes.
 */

#include <stdio.h>
#include <string.h>

#include <kofeng.h>
#include <kgenome.h>
#include "../../libkofeng/analyzers/codenotes.h"
#include "../../libkofeng/analyzers/parsers/binaries/funcs.h"

static int fails;

#define CK(c) do { if (!(c)) { printf("  FAIL %s:%d  %s\n", __FILE__, __LINE__, #c); fails++; } } while (0)

/* The notes of the instruction at `at` of kind `kind`: its text, or NULL. */
static const char *note(const struct kof_codenotes *n, uint64_t at, unsigned kind)
{
	uint32_t cnt, i;
	const struct kof_note *x = kof_codenotes_at(n, at, &cnt);

	for (i = 0; i < cnt; i++)
		if (x[i].kind == kind)
			return kof_codenotes_text(n, &x[i]);
	return NULL;
}

static int is(const char *got, const char *want)
{
	if (!got || strcmp(got, want)) {
		printf("  got %s, want %s\n", got ? got : "(none)", want);
		return 0;
	}
	return 1;
}

static const uint8_t blob[] = {
	0x31, 0xc9,                     /* 0  xor ecx,ecx */
	0xb9, 0x03, 0, 0, 0,            /* 2  mov ecx,3 */
	0x90,                           /* 7  nop            <- the loop's top */
	0x49,                           /* 8  dec ecx */
	0x75, 0xfc,                     /* 9  jnz 7 */
	0xe8, 0, 0, 0, 0,               /* 11 call 16 (call $+5) */
	0x5e,                           /* 16 pop esi        <- an entry the code calls */
	0x31, 0xc0,                     /* 17 xor eax,eax */
	0xb8, 0x0b, 0, 0, 0,            /* 19 mov eax,11 */
	0xcd, 0x80,                     /* 24 int 0x80 */
	0xc3,                           /* 26 ret */
	0xe8, 0, 0, 0, 0                /* 27 call 32: the end of the blob, nothing is there */
};

static void t_blob(void)
{
	struct kof_obj_ctx ctx;
	struct kof_codenotes n;
	struct kgenome_func_set none;

	memset(&ctx, 0, sizeof ctx);
	memset(&none, 0, sizeof none);
	ctx.obj_size = sizeof blob;
	CK(kof_codenotes_build(&ctx, kof_buf_make(blob, sizeof blob), &none, NULL, 0, 32, NULL, &n) == 1);

	CK(is(note(&n, 7, KOF_NOTE_LABEL), ".L-7:  ; xrefs: 9 jcc"));
	CK(note(&n, 7, KOF_NOTE_FUNC) == NULL);                 /* a jump's landing is a label and never a function */
	CK(is(note(&n, 9, KOF_NOTE_COMMENT), "-> .L-7 (backward)"));
	CK(is(note(&n, 11, KOF_NOTE_COMMENT), "-> fcn_00000010"));
	/* a call target the (empty) function table does not hold is not a function: a LABEL, spelled as the call that reaches it spells it (FUNC-12: the table is the one answer) */
	CK(is(note(&n, 16, KOF_NOTE_LABEL), "fcn_00000010:  ; xrefs: b call"));
	CK(note(&n, 16, KOF_NOTE_FUNC) == NULL);
	CK(is(note(&n, 24, KOF_NOTE_COMMENT), "linux: execve (11)"));  /* a blob: whose table is said */
	CK(note(&n, 26, KOF_NOTE_COMMENT) == NULL);             /* ret says nothing */
	CK(note(&n, 8, KOF_NOTE_COMMENT) == NULL && note(&n, 8, KOF_NOTE_LABEL) == NULL);   /* a plain instruction has no note */
	CK(strstr(kof_codenotes_text(&n, &n.v[0]), "loop") == NULL);                          /* nothing is called a loop */
	{
		uint32_t i, ord = 1;

		for (i = 1; i < n.n; i++)
			ord &= n.v[i - 1u].at < n.v[i].at || (n.v[i - 1u].at == n.v[i].at && n.v[i - 1u].kind <= n.v[i].kind);
		CK(ord);                                         /* the table is in the order a reader binary-searches */
	}
	kof_codenotes_free(&n);
}

static void t_other_reads(void)
{
	struct kof_obj_ctx ctx;
	struct kof_codenotes n;
	struct kgenome_func_set none;
	static const uint8_t sys[] = { 0x0f, 0x05 };            /* syscall, number held by nothing */

	memset(&ctx, 0, sizeof ctx);
	memset(&none, 0, sizeof none);
	ctx.obj_size = sizeof sys;
	CK(kof_codenotes_build(&ctx, kof_buf_make(sys, sizeof sys), &none, NULL, 0, 64, NULL, &n) == 1);
	CK(is(note(&n, 0, KOF_NOTE_COMMENT), "syscall, number not known here"));   /* never a guess */
	kof_codenotes_free(&n);

	/* no code to read at all: an answer, with nothing in it */
	ctx.obj_size = 0;
	CK(kof_codenotes_build(&ctx, kof_buf_make(sys, 0), &none, NULL, 0, 64, NULL, &n) == 0 && n.n == 0);
	kof_codenotes_free(&n);
}


/*
 * THE NAME OF A FUNCTION NO SYMBOL NAMES IS ONE WORD, kof_func_name's. The disassembly said `sub_<offset>` and the CFG dialog `fcn_<offset>` for the same
 * function: two spellings, in codenotes.c and sym_any.c. Old tests missed it (a) no test put the two surfaces side by side, and (c) each pinned only its
 * own spelling. Here every small offset is the target of a call, of a jump, and (with a table entry) of both: the FUNC note, the xref text and the comment
 * must be the API's string, character for character.
 */
static void t_one_spelling(void)
{
	uint32_t t;
	char want[48], text[96];

	for (t = 0; t < 40; t++) {
		/* 32-bit raw code: 0..39 are nops, then a call/jmp to `t` at 40 and 45 */
		uint8_t code[51];
		struct kof_obj_ctx ctx;
		struct kof_codenotes n;
		struct kgenome_func_set none, fs;
		struct kgenome_func f;
		int with_table;

		memset(code, 0x90, sizeof code);
		code[40] = 0xe8; code[45] = 0xe9;
		{
			const int32_t r1 = (int32_t)t - 45, r2 = (int32_t)t - 50;

			memcpy(code + 41, &r1, 4);
			memcpy(code + 46, &r2, 4);
		}
		code[50] = 0xc3;
		memset(&f, 0, sizeof f);
		f.off = t;
		f.len = 1;
		kof_fcn_name(t, want, sizeof want);
		CK(kof_func_name(&f, NULL, 0, text, sizeof text) == 0 && !strcmp(text, want));
		for (with_table = 0; with_table < 2; with_table++) {
			memset(&ctx, 0, sizeof ctx);
			memset(&none, 0, sizeof none);
			fs = none;
			if (with_table) {
				fs.v = &f;
				fs.n = 1;
			}
			ctx.obj_size = sizeof code;
			CK(kof_codenotes_build(&ctx, kof_buf_make(code, sizeof code), &fs, NULL, 0, 32, NULL, &n) == 1);
			snprintf(text, sizeof text, "-> %s", want);
			CK(is(note(&n, 40, KOF_NOTE_COMMENT), text));         /* a call to it */
			snprintf(text, sizeof text, "-> %s (backward)", want);
			if (with_table)
				CK(is(note(&n, 45, KOF_NOTE_COMMENT), text));  /* a jump to a table entry: a function, named as one */
			snprintf(text, sizeof text, "%s:  ; xrefs: ", want);
			{
				const char *fn = note(&n, t, KOF_NOTE_FUNC);

				const char *lb = note(&n, t, KOF_NOTE_LABEL);

				/* a function of the table is a FUNC; a call target the table lacks is the same text as a LABEL */
				CK(with_table ? (fn && !strncmp(fn, text, strlen(text)) && lb == NULL) : (lb && !strncmp(lb, text, strlen(text)) && fn == NULL));
				CK(fn == NULL || strstr(fn, "sub_") == NULL);
			}
			kof_codenotes_free(&n);
		}
	}
	/* the API itself: offset 0, a 64-bit offset, every capacity; the made-up name alone is the table's name with no symbol */
	{
		static const uint64_t offs[] = { 0, 1, 0xfffffffful, 0x100000000ull, 0x123456789abcdef0ull, UINT64_MAX };
		uint32_t i, cap;

		for (i = 0; i < sizeof offs / sizeof offs[0]; i++)
			for (cap = 1; cap < 24; cap++) {
				struct kgenome_func f;
				char a[24], b[24];

				memset(&f, 0, sizeof f);
				f.off = offs[i];
				kof_fcn_name(offs[i], a, cap);
				CK(kof_func_name(&f, NULL, 0, b, cap) == 0 && !strcmp(a, b) && strlen(a) < cap);
				CK(!strncmp(a, "fcn_", cap < 5 ? cap - 1u : 4u));
			}
		{
			char a[24];

			kof_fcn_name(0, a, sizeof a);
			CK(!strcmp(a, "fcn_00000000"));
			kof_fcn_name(0x123456789abcdef0ull, a, sizeof a);
			CK(!strcmp(a, "fcn_123456789abcdef0"));
		}
	}
}

/* The request: the same notes as the positional adapter; a function of the table nothing refers to still has its FUNC row (the table is where functions come from); a call target the table
 * lacks is a LABEL and a table entry that is also a call target is the FUNC; a walk handed in (empty here: nothing to read from it, so the decode stands in) changes nothing. */
static void t_request(void)
{
	struct kof_obj_ctx ctx;
	struct kof_codenotes a, b, c;
	struct kgenome_func f[2];
	struct kgenome_func_set fs;
	struct kgenome_diag_walk *wk = kgenome_diag_walk_new();
	uint32_t i;

	memset(&ctx, 0, sizeof ctx);
	memset(f, 0, sizeof f);
	f[0].off = 16;          /* the call target of the blob */
	f[0].len = 11;
	f[1].off = 26;          /* the `ret`: nothing refers to it */
	f[1].len = 1;
	memset(&fs, 0, sizeof fs);
	fs.v = f;
	fs.n = 2;
	ctx.obj_size = sizeof blob;
	CK(kof_codenotes_build(&ctx, kof_buf_make(blob, sizeof blob), &fs, NULL, 0, 32, NULL, &a) == 1);
	CK(kof_codenotes_make(&(const struct kof_codenotes_req){ .ctx = &ctx, .data = kof_buf_make(blob, sizeof blob), .funcs = &fs, .bits = 32 }, &b) == 1);
	CK(kof_codenotes_make(&(const struct kof_codenotes_req){ .ctx = &ctx, .data = kof_buf_make(blob, sizeof blob), .funcs = &fs, .bits = 32, .wk = wk }, &c) == 1);
	CK(a.n == b.n && a.n == c.n && a.pool_n == b.pool_n && a.pool_n == c.pool_n);
	for (i = 0; i < a.n && i < b.n && i < c.n; i++)
		CK(a.v[i].at == b.v[i].at && a.v[i].kind == b.v[i].kind && !strcmp(kof_codenotes_text(&a, &a.v[i]), kof_codenotes_text(&b, &b.v[i])) &&
		   a.v[i].at == c.v[i].at && !strcmp(kof_codenotes_text(&a, &a.v[i]), kof_codenotes_text(&c, &c.v[i])));
	CK(is(note(&a, 16, KOF_NOTE_FUNC), "fcn_00000010:  ; xrefs: b call"));      /* the table entry that a call reaches: a function */
	CK(note(&a, 16, KOF_NOTE_LABEL) == NULL);
	CK(note(&a, 26, KOF_NOTE_FUNC) != NULL);                                     /* a table function nothing refers to: still a function */
	kof_codenotes_free(&a);
	kof_codenotes_free(&b);
	kof_codenotes_free(&c);
	kgenome_diag_walk_free(wk);
}

int main(void)
{
	t_blob();
	t_request();
	t_one_spelling();
	t_other_reads();
	if (fails) {
		printf("code_notes: %d failure(s)\n", fails);
		return 1;
	}
	printf("code_notes: ok\n");
	return 0;
}
