/*
 * emu_borrow_account - the machine charges memory as it takes it, and a page borrowed
 * from the caller's bytes is the caller's until a store copies it.
 *
 * Two promises, each asserted from outside:
 *
 *   ACCOUNTING. cfg.account is asked before the machine takes memory and told what it gives
 *   back: the table at creation, private pages in chunks of KGENOME_EMU_GRANT_PAGES, snapshots
 *   exactly. A borrowed page costs nothing; the first store to it costs one page. A refusal
 *   fails the store (the guest sees a fault, the host's bytes are untouched) and the machine
 *   says so with KGENOME_EMU_HIT_MEM. When the machine is freed the net charge is zero.
 *
 *   COPY ON WRITE. The host image passed to kgenome_emu_map_borrow is NEVER modified by a
 *   guest: by a host write call, by a store that straddles two borrowed pages, by `rep stos`
 *   over several, by self-modifying code, or through a fork of a template that borrows.
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include <phenotype/emu.h>

static int failures;

#define CK(c) do { if (!(c)) { printf("  FAIL %s:%d  %s\n", __FILE__, __LINE__, #c); failures++; } } while (0)

#define PG        KGENOME_EMU_PAGE
#define CODE_VA   0x400000ull
#define IMG_PAGES 128u
#define STACK_VA  0x7ffff000ull

static uint8_t host[IMG_PAGES * PG] __attribute__((aligned(4096)));
static uint8_t keep[IMG_PAGES * PG];

struct acct {
	int64_t net;            /* granted minus returned */
	uint64_t calls;
	int64_t limit;          /* refuse when net + bytes would pass it; <0 = no limit */
};

static int account(void *u, int64_t bytes)
{
	struct acct *a = u;

	a->calls++;
	if (bytes > 0 && a->limit >= 0 && a->net + bytes > a->limit)
		return 0;
	a->net += bytes;
	return 1;
}

static struct kgenome_emu *make(struct acct *a, int borrow)
{
	struct kgenome_emu_cfg cfg;
	struct kgenome_emu *e;

	memset(&cfg, 0, sizeof cfg);
	cfg.max_insn = 100000;
	cfg.max_pages = 4096;
	cfg.account = a ? account : NULL;
	cfg.account_user = a;
	e = kgenome_emu_new(&cfg);
	if (!e)
		return NULL;
	if (!(borrow ? kgenome_emu_map_borrow : kgenome_emu_map)(e, CODE_VA, host, sizeof host,
			sizeof host, KGENOME_EMU_R | KGENOME_EMU_W | KGENOME_EMU_X) ||
	    !kgenome_emu_map(e, STACK_VA, NULL, 0, PG, KGENOME_EMU_R | KGENOME_EMU_W)) {
		kgenome_emu_free(e);
		return NULL;
	}
	return e;
}

static void accounting(void)
{
	struct acct a = { 0, 0, -1 };
	struct kgenome_emu *e = make(&a, 1);
	int64_t base, i;
	uint8_t b = 0x5a;

	CK(e != NULL);
	if (!e)
		return;
	base = a.net;
	/* the table and the cache were charged at creation, once */
	CK(base > 0);
	/* borrowing 128 pages cost nothing more; the 1-page stack and the vsyscall page are
	 * the machine's own private/shared pages and cost at most one chunk */
	CK(a.net - base == 0);
	/* the first store to a borrowed page: one chunk granted, exactly one page used */
	CK(kgenome_emu_write(e, CODE_VA + 5, &b, 1));
	CK(a.net - base <= (int64_t)(KGENOME_EMU_GRANT_PAGES * PG) + 0);
	{
		int64_t after_one = a.net;

		/* the next 62 pages fit in the same chunk */
		for (i = 1; i < 60; i++)
			CK(kgenome_emu_write(e, CODE_VA + (uint64_t)i * PG, &b, 1));
		CK(a.net == after_one);
		/* all 128 pages written: two chunks in all, not 128 pages up front */
		for (i = 60; i < IMG_PAGES; i++)
			CK(kgenome_emu_write(e, CODE_VA + (uint64_t)i * PG, &b, 1));
		CK(a.net - base <= (int64_t)(3u * KGENOME_EMU_GRANT_PAGES * PG));
		CK(a.net - base >= (int64_t)(IMG_PAGES * PG));
	}
	kgenome_emu_free(e);
	CK(a.net == 0);                 /* everything given back, once */

	/* the old way: copy the image, and pay for every page whether stored to or not */
	memset(&a, 0, sizeof a);
	a.limit = -1;
	e = make(&a, 0);
	CK(e != NULL);
	if (e) {
		CK(a.net >= base + (int64_t)(IMG_PAGES * PG));
		kgenome_emu_free(e);
		CK(a.net == 0);
	}
}

static void refusal(void)
{
	struct acct a = { 0, 0, -1 };
	struct kgenome_emu *e = make(&a, 1);
	uint8_t b = 0x77;
	int64_t cap;

	CK(e != NULL);
	if (!e)
		return;
	/* room for the chunk the first store asks for, and then no more */
	cap = a.net + (int64_t)(KGENOME_EMU_GRANT_PAGES * PG);
	a.limit = cap;
	memcpy(keep, host, sizeof host);
	{
		unsigned i, ok = 0;

		for (i = 0; i < IMG_PAGES; i++)
			ok += kgenome_emu_write(e, CODE_VA + (uint64_t)i * PG + 9, &b, 1) ? 1u : 0u;
		/* the machine had what was left of its first chunk and was allowed one more: so
		 * most of the pages could be stored to, and the rest were refused */
		CK(ok > KGENOME_EMU_GRANT_PAGES && ok < IMG_PAGES);
	}
	CK(kgenome_emu_hit(e) & KGENOME_EMU_HIT_MEM);
	/* a refused store left no trace in what the host holds */
	CK(!memcmp(host, keep, sizeof host));
	kgenome_emu_free(e);
	CK(a.net == 0);
}

/* the machine code of each adversary */
static const uint8_t smc[] = {
	0xC6, 0x05, 0x00, 0x00, 0x00, 0x00, 0x90,   /* 0: mov byte [rip+0], 0x90   (target = +7) */
	0xCC,                                       /* 7: int3 -> becomes nop */
	0xEB, 0xFE                                  /* 8: jmp $ */
};
static const uint8_t stos[] = {
	0x48, 0xBF, 0, 0, 0, 0, 0, 0, 0, 0,         /* 0: movabs rdi, VA */
	0xB9, 0x00, 0x30, 0x00, 0x00,               /* 10: mov ecx, 0x3000 */
	0xB0, 0x41,                                 /* 15: mov al, 'A' */
	0xF3, 0xAA,                                 /* 17: rep stosb */
	0xEB, 0xFE                                  /* 19: jmp $ */
};

static void copy_on_write(void)
{
	struct kgenome_emu *e;
	uint8_t b, buf[16];
	uint64_t last = CODE_VA + 20u * PG - 4u;

	/* every page of the host image is distinct, so a leak shows */
	{
		unsigned i;

		for (i = 0; i < sizeof host; i++)
			host[i] = (uint8_t)(i * 31u + (i >> 12));
	}
	memcpy(keep, host, sizeof host);

	/* 1. a host write call, and a read back through the guest's own view */
	e = make(NULL, 1);
	CK(e != NULL);
	if (!e)
		return;
	b = 0xEE;
	CK(kgenome_emu_write(e, CODE_VA + 3u * PG + 7u, &b, 1));
	CK(kgenome_emu_read(e, CODE_VA + 3u * PG + 7u, &b, 1) && b == 0xEE);
	CK(!memcmp(host, keep, sizeof host));
	/* 2. a store straddling two borrowed pages */
	memset(buf, 0xA5, 8);
	CK(kgenome_emu_write(e, last, buf, 8));
	CK(kgenome_emu_read(e, last, buf, 8) && buf[0] == 0xA5 && buf[7] == 0xA5);
	CK(!memcmp(host, keep, sizeof host));
	/* the bytes next to a stored one are the image's, not zeroes */
	CK(kgenome_emu_read(e, CODE_VA + 3u * PG + 8u, &b, 1) && b == keep[3u * PG + 8u]);
	kgenome_emu_free(e);

	/* 3. rep stosb over three borrowed pages, run by the interpreter */
	{
		uint8_t code[sizeof stos];

		memcpy(code, stos, sizeof code);
		memcpy(code + 2, &(uint64_t){ CODE_VA + 40u * PG }, 8);
		/* the code lives in a page of its own, mapped from the same host image */
		memcpy(host + 100u * PG, code, sizeof code);
		memcpy(keep + 100u * PG, code, sizeof code);
		e = make(NULL, 1);
		CK(e != NULL);
		if (e) {
			kgenome_emu_set_rip(e, CODE_VA + 100u * PG);
			kgenome_emu_set_reg(e, KGENOME_EMU_RSP, STACK_VA + 0x800);
			(void)kgenome_emu_run(e);
			CK(kgenome_emu_read(e, CODE_VA + 40u * PG + 0x2fffu, &b, 1) && b == 0x41);
			CK(kgenome_emu_read(e, CODE_VA + 43u * PG, &b, 1) && b == keep[43u * PG]);
			CK(!memcmp(host, keep, sizeof host));
			kgenome_emu_free(e);
		}
	}

	/* 4. self-modifying code in a borrowed page: the run sees its own store, the host does not */
	memcpy(host + 101u * PG, smc, sizeof smc);
	memcpy(keep + 101u * PG, smc, sizeof smc);
	e = make(NULL, 1);
	CK(e != NULL);
	if (e) {
		enum kgenome_emu_stop st;

		kgenome_emu_set_rip(e, CODE_VA + 101u * PG);
		kgenome_emu_set_reg(e, KGENOME_EMU_RSP, STACK_VA + 0x800);
		st = kgenome_emu_run(e);
		/* int3 at +7 was overwritten with a nop before it was reached: the run got to the
		 * jump (ends on the budget), it did not stop at a breakpoint or fault */
		CK(st == KGENOME_EMU_STOP_BUDGET);
		CK(kgenome_emu_read(e, CODE_VA + 101u * PG + 7u, &b, 1) && b == 0x90);
		CK(!memcmp(host, keep, sizeof host));
		kgenome_emu_free(e);
	}

	/* 5. a fork of a template that borrows: the fork's store reaches neither */
	e = make(NULL, 1);
	CK(e != NULL);
	if (e) {
		struct kgenome_emu *f = kgenome_emu_fork(e);

		CK(f != NULL);
		if (f) {
			b = 0x11;
			CK(kgenome_emu_write(f, CODE_VA + 9u * PG, &b, 1));
			CK(kgenome_emu_read(f, CODE_VA + 9u * PG, &b, 1) && b == 0x11);
			CK(kgenome_emu_read(e, CODE_VA + 9u * PG, &b, 1) && b == keep[9u * PG]);
			CK(!memcmp(host, keep, sizeof host));
			kgenome_emu_free(f);
		}
		kgenome_emu_free(e);
	}
}

int main(void)
{
	accounting();
	refusal();
	copy_on_write();
	printf("emu borrow/account: %s\n", failures ? "FAILED" : "ok");
	return failures != 0;
}
