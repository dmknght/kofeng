/*
 * callnames - the engine's side of the call-name table: how an entry is SPELLED (kof_callnames_name), that the code notes use the names
 * (kof_codenotes_build with a table), and the oracle dump.
 *
 * The images are the lib test's (tests/lib/genome/callnames_img.h), so the expected table is known from the layout. What it pins: `name@plt` for a stub and `name@got` for
 * an instruction through its slot, and never the other way (a TARGET lookup of a SLOT entry and a SITE lookup of a stub are no answer); the PE's own spelling `dll!name`
 * and `dll!#ordinal`; a destination of any size (every capacity from 0 to 40 ends in a NUL and never writes past it); a name with no terminator is bounded by the
 * object; offset 0 and UINT64_MAX are no entry; the notes say `-> rand@plt` with the table and `-> fcn_00000310` without it.
 *
 * With an argument, it is the ORACLE'S DUMP instead: `callnames <file>` prints one line `<address> <spelling>` for every STUB entry of the file, which
 * tests/callnames_oracle.py compares with objdump's `<name@plt>` labels.
 */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <kgenome.h>
#include "../../libkofeng/analyzers/callnames.h"
#include "../../libkofeng/analyzers/codenotes.h"
#include "../../libkofeng/analyzers/genome_obj.h"
#include "../lib/genome/hk.h"
#include "../lib/genome/callnames_img.h"

static uint8_t E[CI_ELF_SIZE];

static void ctx_of(struct kof_obj_ctx *ctx, const struct kgenome_obj *o)
{
	memset(ctx, 0, sizeof *ctx);
	kof_genome_obj_store(ctx, o);
}

static const char *name(const struct kgenome_callnames *t, kof_buf d, enum kof_callname_via via, uint64_t off)
{
	static char buf[128];

	return kof_callnames_name(t, d, via, off, buf, sizeof buf) ? buf : NULL;
}

static int same(const char *got, const char *want)
{
	if (!want)
		return got == NULL;
	return got && !strcmp(got, want);
}

static const char *note(const struct kof_codenotes *n, uint64_t at, unsigned kind)
{
	uint32_t cnt, i;
	const struct kof_note *x = kof_codenotes_at(n, at, &cnt);

	for (i = 0; i < cnt; i++)
		if (x[i].kind == kind)
			return kof_codenotes_text(n, &x[i]);
	return NULL;
}

static void t_elf(void)
{
	struct kgenome_elf_info ei;
	struct kgenome_obj o;
	struct kof_obj_ctx ctx;
	struct kgenome_callnames t;
	struct kof_codenotes n;
	struct kgenome_func_set none;
	const kof_buf d = kof_buf_make(E, CI_ELF_SIZE);
	char small[48];
	unsigned cap;

	ci_elf(E);
	memset(&ei, 0, sizeof ei);
	CK(kgenome_elf_image_parse(d, &ei, &o));
	o.file_header = &ei;
	ctx_of(&ctx, &o);
	CK(kof_callnames_applicable(&ctx));
	CK(kof_callnames_build(&ctx, d, NULL, &t) == 1 && t.status == KGENOME_OK);
	CK(same(name(&t, d, KOF_CALLNAME_VIA_TARGET, 0x310), "rand@plt"));
	CK(same(name(&t, d, KOF_CALLNAME_VIA_TARGET, 0x320), "puts@plt"));
	CK(same(name(&t, d, KOF_CALLNAME_VIA_TARGET, 0x400), "exit@plt"));
	CK(same(name(&t, d, KOF_CALLNAME_VIA_TARGET, 0x404), "exit@plt"));
	CK(same(name(&t, d, KOF_CALLNAME_VIA_SITE, 0x505), "puts@got"));
	CK(same(name(&t, d, KOF_CALLNAME_VIA_SITE, 0x510), "rand@got"));
	/* the wrong question gets no answer: a stub's own jump is not a call through a slot, a call through a slot is not a place to land on */
	CK(same(name(&t, d, KOF_CALLNAME_VIA_SITE, 0x310), NULL));
	CK(same(name(&t, d, KOF_CALLNAME_VIA_SITE, 0x404), NULL));
	CK(same(name(&t, d, KOF_CALLNAME_VIA_TARGET, 0x505), NULL));
	CK(same(name(&t, d, KOF_CALLNAME_VIA_TARGET, 0), NULL) && same(name(&t, d, KOF_CALLNAME_VIA_TARGET, UINT64_MAX), NULL));
	CK(!kof_callnames_name(NULL, d, KOF_CALLNAME_VIA_TARGET, 0x310, small, sizeof small));      /* no table: no name, no crash */
	/* any destination size: terminated, and the name is the whole name or a cut of it */
	for (cap = 0; cap <= 40; cap++) {
		char dst[48];
		int r;

		memset(dst, 'Z', sizeof dst);
		r = kof_callnames_name(&t, d, KOF_CALLNAME_VIA_TARGET, 0x310, dst, cap);
		CK(dst[cap] == 'Z' || cap >= sizeof dst);       /* never written past the capacity */
		if (cap)
			CK(memchr(dst, 0, cap) != NULL);
		CK(cap >= 10 ? r == 1 && !strcmp(dst, "rand@plt") : r == 0 || (r == 1 && cap >= 6));
	}
	/* the notes: with the table the stub has its name and a call to it says so; without it, `fcn_<offset>` (kof_func_name) */
	memset(&none, 0, sizeof none);
	CK(kof_codenotes_build(&ctx, d, &none, NULL, 0, 0, &t, &n) == 1);
	CK(note(&n, 0x500, KOF_NOTE_COMMENT) && !strcmp(note(&n, 0x500, KOF_NOTE_COMMENT), "-> rand@plt"));
	CK(note(&n, 0x505, KOF_NOTE_COMMENT) && !strcmp(note(&n, 0x505, KOF_NOTE_COMMENT), "-> puts@got"));
	CK(note(&n, 0x50b, KOF_NOTE_COMMENT) && !strcmp(note(&n, 0x50b, KOF_NOTE_COMMENT), "-> exit@plt"));
	CK(note(&n, 0x310, KOF_NOTE_FUNC) && !strncmp(note(&n, 0x310, KOF_NOTE_FUNC), "rand@plt:", 9));
	kof_codenotes_free(&n);
	CK(kof_codenotes_build(&ctx, d, &none, NULL, 0, 0, NULL, &n) == 1);
	CK(note(&n, 0x500, KOF_NOTE_COMMENT) && !strcmp(note(&n, 0x500, KOF_NOTE_COMMENT), "-> fcn_00000310"));
	CK(!note(&n, 0x505, KOF_NOTE_COMMENT));
	kof_codenotes_free(&n);
	kgenome_callnames_free(&t, NULL);
	/* a name with no terminator: bounded by the dynstr's end... and by the object */
	memset(E + CI_DYNSTR + 1, 'A', 14);
	CK(kof_callnames_build(&ctx, d, NULL, &t) == 1);
	{
		char dst[64];

		CK(kof_callnames_name(&t, d, KOF_CALLNAME_VIA_TARGET, 0x310, dst, sizeof dst) == 1);
		CK(strlen(dst) < sizeof dst && !strncmp(dst, "AAAA", 4) && !strcmp(dst + strlen(dst) - 4, "@plt"));
	}
	kgenome_callnames_free(&t, NULL);
}

static void t_pe(int plus)
{
	struct hk_pe P;
	struct kgenome_pe_info pi;
	struct kgenome_obj o;
	struct kof_obj_ctx ctx;
	struct kgenome_callnames t;
	kof_buf dd;

	hk_pe(&P, plus);
	ci_pe_code(&P);
	memset(&pi, 0, sizeof pi);
	dd = kof_buf_make(P.b, P.n);
	CK(kgenome_pe_image_parse(dd, &pi, &o));
	o.file_header = &pi;
	ctx_of(&ctx, &o);
	CK(kof_callnames_build(&ctx, dd, NULL, &t) == 1 && t.status == KGENOME_OK);
	CK(same(name(&t, dd, KOF_CALLNAME_VIA_SITE, 0x200), "kernel32.dll!ExitProcess"));
	CK(same(name(&t, dd, KOF_CALLNAME_VIA_TARGET, 0x206), "user32.dll!MessageBoxA"));
	CK(same(name(&t, dd, KOF_CALLNAME_VIA_TARGET, 0x20c), "kernel32.dll!#5"));
	CK(same(name(&t, dd, KOF_CALLNAME_VIA_SITE, 0x206), NULL) && same(name(&t, dd, KOF_CALLNAME_VIA_TARGET, 0x200), NULL));
	kgenome_callnames_free(&t, NULL);
}

/* The oracle's dump: every STUB entry of the file, as `<address> <spelling>`. */
static int dump(const char *path)
{
	FILE *f = fopen(path, "rb");
	uint8_t *b;
	long n;
	struct kgenome_elf_info ei;
	struct kgenome_obj o;
	struct kof_obj_ctx ctx;
	struct kgenome_callnames t;
	uint32_t i;
	kof_buf d;
	char nm[KGENOME_SYMNAME_MAX + 8];
	struct timespec t0, t1;
	int ok;

	if (!f)
		return 2;
	fseek(f, 0, SEEK_END);
	n = ftell(f);
	fseek(f, 0, SEEK_SET);
	if (n <= 0 || n > (64l << 20) || !(b = malloc((size_t)n))) {
		fclose(f);
		return 2;
	}
	if (fread(b, 1, (size_t)n, f) != (size_t)n) {
		fclose(f);
		free(b);
		return 2;
	}
	fclose(f);
	d = kof_buf_make(b, (uint64_t)n);
	memset(&ei, 0, sizeof ei);
	if (!kgenome_elf_image_parse(d, &ei, &o)) {
		puts("NOTELF");
		free(b);
		return 0;
	}
	o.file_header = &ei;
	ctx_of(&ctx, &o);
	clock_gettime(CLOCK_MONOTONIC, &t0);
	ok = kof_callnames_build(&ctx, d, NULL, &t);
	clock_gettime(CLOCK_MONOTONIC, &t1);
	if (!ok) {
		printf("NA %s\n", kgenome_status_name(t.status));
		free(b);
		return 0;
	}
	for (i = 0; i < t.n; i++)
		if (t.v[i].kind == KGENOME_CALLNAME_STUB &&
		    kof_callnames_name(&t, d, KOF_CALLNAME_VIA_TARGET, t.v[i].off, nm, sizeof nm))
			printf("%llx %s\n", (unsigned long long)kgenome_image_off_to_addr(&o, t.v[i].off), nm);
	printf("STATUS %s n=%u bytes=%llu insns=%llu size=%ld ms=%.3f\n", kgenome_status_name(t.status), t.n, (unsigned long long)t.bytes,
	       (unsigned long long)t.insns, n, (double)(t1.tv_sec - t0.tv_sec) * 1e3 + (double)(t1.tv_nsec - t0.tv_nsec) / 1e6);
	kgenome_callnames_free(&t, NULL);
	free(b);
	return 0;
}

int main(int argc, char **argv)
{
	if (argc > 1)
		return dump(argv[1]);
	t_elf();
	t_pe(1);
	t_pe(0);
	if (hk_fails) {
		printf("callnames: %d failure(s)\n", hk_fails);
		return 1;
	}
	printf("callnames: ok\n");
	return 0;
}
