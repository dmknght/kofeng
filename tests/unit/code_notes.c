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
#include "../../libkofeng/analyzers/codenotes.h"

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
	CK(kof_codenotes_build(&ctx, kof_buf_make(blob, sizeof blob), &none, NULL, 0, 32, &n) == 1);

	CK(is(note(&n, 7, KOF_NOTE_LABEL), ".L-7:  ; xrefs: 9 jcc"));
	CK(note(&n, 7, KOF_NOTE_FUNC) == NULL);                 /* a jump's landing is a label and never a function */
	CK(is(note(&n, 9, KOF_NOTE_COMMENT), "-> .L-7 (backward)"));
	CK(is(note(&n, 11, KOF_NOTE_COMMENT), "-> sub_10"));
	CK(is(note(&n, 16, KOF_NOTE_FUNC), "sub_10:  ; xrefs: b call"));
	CK(note(&n, 16, KOF_NOTE_LABEL) == NULL);
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
	CK(kof_codenotes_build(&ctx, kof_buf_make(sys, sizeof sys), &none, NULL, 0, 64, &n) == 1);
	CK(is(note(&n, 0, KOF_NOTE_COMMENT), "syscall, number not known here"));   /* never a guess */
	kof_codenotes_free(&n);

	/* no code to read at all: an answer, with nothing in it */
	ctx.obj_size = 0;
	CK(kof_codenotes_build(&ctx, kof_buf_make(sys, 0), &none, NULL, 0, 64, &n) == 0 && n.n == 0);
	kof_codenotes_free(&n);
}

int main(void)
{
	t_blob();
	t_other_reads();
	if (fails) {
		printf("code_notes: %d failure(s)\n", fails);
		return 1;
	}
	printf("code_notes: ok\n");
	return 0;
}
