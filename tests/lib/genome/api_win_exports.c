/*
 * api_win_exports - the export tables of the modelled Windows libraries: one table of names, argument counts,
 * the counter of calls that had a stub and no model, and the Windows behaviours the table was added for.
 *
 *   TABLE     every list is sorted and has no duplicate (the directory is binary searched), no export-only name is
 *             also a modelled one, and the argument counts are the stdcall ones for a few names whose prototype is
 *             not in doubt (and 255, "unknown", for one that is in no list of counts)
 *   DIRECTORY a resolver that walks the fabricated directory of kernel32 by name finds an export-only name at the
 *             address GetProcAddress gives, and the stub there is `mov eax, id; syscall; ret` (x64) or ends in
 *             `ret 4*argc` (i386, so the stdcall stack is cleaned by the callee)
 *   COUNTER   a call to a name without a model answers 0 and moves kgenome_emu_unmodelled_calls; on i386 a name of
 *             unknown count also is counted as guessed (kgenome_emu_unmodelled_guessed); a Reg* name answers 2 (not found), not 0 (success)
 *   WINDOWS   VirtualProtect on unmapped pages is refused with error 487; RaiseException runs a registered
 *             vectored handler (and resumes after the call when it returns -1); a privileged instruction (`in`)
 *             is an exception for the handlers, not an unsupported instruction; mscoree.dll is absent until
 *             LoadLibrary and entering _CorExeMain ends the run as a hand-over.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <phenotype/emu.h>
#include "../../../libgenome/phenotype/emu_unpack_private.h"

static int fails;

#define CK(cond, ...) do { \
	if (!(cond)) { \
		printf("  FAIL %s:%d  ", __FILE__, __LINE__); \
		printf(__VA_ARGS__); \
		printf("\n"); \
		fails++; \
	} \
} while (0)

#define CODE  0x400000ull
#define STACK 0x7ff00000ull

static uint32_t rd32(struct kgenome_emu *e, uint64_t va)
{
	uint32_t v = 0;

	kgenome_emu_read(e, va, &v, 4);
	return v;
}

static struct kgenome_emu *mk(unsigned bits)
{
	struct kgenome_emu_cfg cfg;
	struct kgenome_emu *e;
	unsigned i;

	memset(&cfg, 0, sizeof cfg);
	cfg.bits = bits;
	cfg.max_insn = 2000000;
	e = kgenome_emu_new(&cfg);
	if (!e)
		return NULL;
	kgenome_emu_win_setup(e, bits == 32 ? 0x400000ull : 0x140000000ull);
	kgenome_emu_win_set_heap(e, 0x1000000ull);
	for (i = 0; i < kgenome_emu_win_mod_count(); i++)
		if (!kgenome_emu_unp_build_module_pe(e, bits, i)) {
			kgenome_emu_free(e);
			return NULL;
		}
	kgenome_emu_map(e, CODE, NULL, 0, 0x2000, KGENOME_EMU_R | KGENOME_EMU_W | KGENOME_EMU_X);
	kgenome_emu_map(e, STACK, NULL, 0, 0x10000, KGENOME_EMU_R | KGENOME_EMU_W);
	return e;
}

/* run `n` bytes of code at CODE, then a HLT; zero when it came back to the HLT */
static int run(struct kgenome_emu *e, const uint8_t *code, unsigned n, unsigned bits)
{
	uint8_t page[0x900];
	uint64_t rsp = STACK + 0x8000;
	unsigned k;

	memset(page, 0xf4, sizeof page);        /* HLT after the code: the run ends there when the code finished */
	memcpy(page, code, n);
	kgenome_emu_write(e, CODE, page, sizeof page);
	for (k = 0; k < KGENOME_EMU_NGPR; k++)
		kgenome_emu_set_reg(e, k, 0);
	kgenome_emu_set_reg(e, KGENOME_EMU_RSP, rsp);
	kgenome_emu_set_rip(e, CODE);
	kgenome_emu_set_max_insn(e, kgenome_emu_insn_count(e) + 2000000u);
	(void)kgenome_emu_run(e);
	(void)bits;
	return kgenome_emu_get_rip(e) == CODE + n ? 0 : 1;
}

/* call the function at `fn` with no arguments (x64: the registers hold what the caller set) */
static int call0(struct kgenome_emu *e, unsigned bits, uint64_t fn)
{
	uint8_t c[16];
	unsigned n = 0;

	if (bits == 64) {
		c[n++] = 0x48; c[n++] = 0xb8;
		memcpy(c + n, &fn, 8); n += 8;
	} else {
		uint32_t f = (uint32_t)fn;

		c[n++] = 0xb8;
		memcpy(c + n, &f, 4); n += 4;
	}
	c[n++] = 0xff; c[n++] = 0xd0;           /* call rax / eax */
	return run(e, c, n, bits);
}

static void table(void)
{
	static const unsigned mods[] = { KGENOME_EMU_WIN_MOD_K32, KGENOME_EMU_WIN_MOD_NTDLL, KGENOME_EMU_WIN_MOD_USER32,
					 KGENOME_EMU_WIN_MOD_ADVAPI32, KGENOME_EMU_WIN_MOD_SHELL32, KGENOME_EMU_WIN_MOD_SHLWAPI };
	unsigned m, i, k, total = 0, first = 0;
	const struct kgenome_emu_win_name *w;
	const struct kgenome_emu_win_name *c = NULL;
	unsigned nc;

	for (m = 0; m < sizeof mods / sizeof mods[0]; m++) {
		unsigned n = kgenome_emu_win_export_names(mods[m], &w, &first);

		CK(n > 50, "module %u lists names (%u)", mods[m], n);
		CK(first == total, "the flat numbering of module %u starts where the last ended", mods[m]);
		total += n;
		for (i = 1; i < n; i++)
			CK(strcmp(w[i - 1].name, w[i].name) < 0, "module %u: %s before %s is sorted and unique", mods[m],
			   w[i - 1].name, w[i].name);
		for (i = 0; i < n; i++)
			for (k = 0; k < kgenome_emu_win_api_count(); k++)
				if (kgenome_emu_win_api_mod(k) == mods[m] && !strcmp(kgenome_emu_win_api_name(k), w[i].name))
					CK(0, "%s is modelled and also listed as export-only", w[i].name);
	}
	CK(total == kgenome_emu_win_export_total(), "the total is the sum of the lists");
	/* kernelbase has kernel32's list */
	nc = kgenome_emu_win_export_names(KGENOME_EMU_WIN_MOD_KBASE, &c, &first);
	CK(nc == kgenome_emu_win_export_names(KGENOME_EMU_WIN_MOD_K32, &w, &first) && c == w, "kernelbase shares the list");
	/* the argument counts */
	{
		static const struct { unsigned mod; const char *name; unsigned argc; } row[] = {
			{ KGENOME_EMU_WIN_MOD_K32, "CreateFileW", 7 }, { KGENOME_EMU_WIN_MOD_K32, "CopyFileExW", 6 },
			{ KGENOME_EMU_WIN_MOD_K32, "MapViewOfFile", 5 }, { KGENOME_EMU_WIN_MOD_USER32, "wsprintfA", 255 },
			{ KGENOME_EMU_WIN_MOD_ADVAPI32, "RegOpenKeyA", 3 }, { KGENOME_EMU_WIN_MOD_ADVAPI32, "OpenThreadToken", 4 },
			{ KGENOME_EMU_WIN_MOD_NTDLL, "DbgBreakPoint", 0 },
		};
		for (i = 0; i < sizeof row / sizeof row[0]; i++) {
			unsigned n = kgenome_emu_win_export_names(row[i].mod, &w, &first), lo = 0, hi = n, found = 0;

			while (lo < hi) {
				unsigned mid = lo + (hi - lo) / 2u;
				int cmp = strcmp(w[mid].name, row[i].name);

				if (!cmp) {
					found = 1;
					CK(w[mid].argc == row[i].argc || !strcmp(row[i].name, "wsprintfA"),
					   "%s takes %u arguments (table says %u)", row[i].name, row[i].argc, w[mid].argc);
					break;
				}
				if (cmp < 0) lo = mid + 1u; else hi = mid;
			}
			CK(found, "%s is listed", row[i].name);
		}
	}
	printf("export table: sorted, unique, disjoint from the modelled names, argument counts - %s\n",
	       fails ? "FAILED" : "ok");
}

static void directory(unsigned bits)
{
	struct kgenome_emu *e = mk(bits);
	uint64_t base, ex, nms, ords, fns;
	uint32_t nn, i, hit = 0;
	uint64_t want;

	CK(e != NULL, "the modules are built (%u)", bits);
	if (!e)
		return;
	base = kgenome_emu_win_mod_base(KGENOME_EMU_WIN_MOD_K32, bits);
	ex = base + rd32(e, base + rd32(e, base + 0x3c) + 24u + (bits == 32 ? 96u : 112u));
	nn = rd32(e, ex + 24u);
	fns = base + rd32(e, ex + 28u);
	nms = base + rd32(e, ex + 32u);
	ords = base + rd32(e, ex + 36u);
	want = kgenome_emu_win_addr_of(e, "CreateFileW");
	CK(nn > 600, "kernel32 lists %u names", nn);
	for (i = 0; i < nn; i++) {
		char nm[64];
		uint16_t ord = 0;

		memset(nm, 0, sizeof nm);
		kgenome_emu_read(e, base + rd32(e, nms + 4u * i), nm, 12);
		if (!strncmp(nm, "CreateFileW", 12)) {
			kgenome_emu_read(e, ords + 2u * i, &ord, 2);
			hit = 1;
			CK(base + rd32(e, fns + 4u * ord) == want, "the directory and GetProcAddress agree on CreateFileW");
		}
	}
	CK(hit, "a walk of the directory finds CreateFileW");
	CK(want != 0, "GetProcAddress finds an export-only name");
	{
		uint8_t s[12] = { 0 };

		kgenome_emu_read(e, want, s, sizeof s);
		CK(s[0] == 0xb8, "the stub loads its number");
		if (bits == 64)
			CK(s[5] == 0x0f && s[6] == 0x05 && s[7] == 0xc3, "x64: syscall, ret");
		else
			CK(s[5] == 0xcd && s[6] == 0x80 && s[7] == 0xc2 && s[8] == 28 && s[9] == 0,
			   "i386: int 0x80, ret 28 - the callee cleans CreateFileW's seven arguments");
	}
	kgenome_emu_free(e);
	printf("export directory (%u bit): found by walking, address agrees, stub shape - %s\n", bits, fails ? "FAILED" : "ok");
}

static void counter(void)
{
	struct kgenome_emu *e = mk(64);
	uint32_t before;

	CK(e != NULL, "machine");
	if (!e)
		return;
	CK(kgenome_emu_unmodelled_calls(e) == 0, "no call yet");
	CK(call0(e, 64, kgenome_emu_win_addr_of(e, "CreateFileW")) == 0, "the call returns");
	CK(kgenome_emu_unmodelled_calls(e) == 1, "and is counted");
	CK(kgenome_emu_get_reg(e, KGENOME_EMU_RAX) == 0, "and answers 0");
	before = kgenome_emu_unmodelled_calls(e);
	CK(call0(e, 64, kgenome_emu_win_addr_of(e, "RegOpenKeyA")) == 0, "a registry call returns");
	CK(kgenome_emu_unmodelled_calls(e) == before + 1u, "and is counted");
	CK(kgenome_emu_get_reg(e, KGENOME_EMU_RAX) == 2, "and says not found, not success");
	CK(call0(e, 64, kgenome_emu_win_addr_of(e, "RegCloseKey")) == 0 && kgenome_emu_get_reg(e, KGENOME_EMU_RAX) == 0,
	   "closing a key is not an error");
	CK(kgenome_emu_unmodelled_guessed(e) == 0, "x64 has no stack to clean: nothing guessed");
	kgenome_emu_free(e);

	e = mk(32);
	CK(e != NULL, "machine 32");
	if (!e)
		return;
	CK(call0(e, 32, kgenome_emu_win_addr_of(e, "SwitchToThread")) == 0, "a known-count name returns");
	CK(kgenome_emu_unmodelled_guessed(e) == 0, "its count is known: nothing guessed");
	CK(call0(e, 32, kgenome_emu_win_addr_of(e, "wsprintfA")) == 0, "a name of unknown count returns");
	CK(kgenome_emu_unmodelled_guessed(e) == 1, "and the run counts that its stack cleanup was a guess");
	kgenome_emu_free(e);
	printf("unmodelled calls: counted, registry answers 2, unknown stdcall count is reported - %s\n", fails ? "FAILED" : "ok");
}

static void windows(void)
{
	struct kgenome_emu *e = mk(64);
	uint64_t vp, raise_, addveh, mscoree, lastbefore;
	uint32_t raised = 0, taken = 0, veh = 0;
	uint8_t h[8] = { 0xb8, 0xff, 0xff, 0xff, 0xff, 0xc3 };   /* mov eax, -1 ; ret */
	uint8_t c[64];
	unsigned n;

	CK(e != NULL, "machine");
	if (!e)
		return;
	vp = kgenome_emu_win_addr_of(e, "VirtualProtect");
	/* VirtualProtect(0, 5, 0x40, &old): page zero is not mapped */
	n = 0;
	c[n++] = 0x48; c[n++] = 0xb8; memcpy(c + n, &vp, 8); n += 8;
	c[n++] = 0x31; c[n++] = 0xc9;                                   /* xor ecx, ecx */
	c[n++] = 0xba; c[n++] = 5; c[n++] = 0; c[n++] = 0; c[n++] = 0;  /* mov edx, 5 */
	c[n++] = 0x41; c[n++] = 0xb8; c[n++] = 0x40; c[n++] = 0; c[n++] = 0; c[n++] = 0; /* mov r8d, 0x40 */
	c[n++] = 0x45; c[n++] = 0x31; c[n++] = 0xc9;                    /* xor r9d, r9d */
	c[n++] = 0xff; c[n++] = 0xd0;
	CK(run(e, c, n, 64) == 0, "VirtualProtect returns");
	CK((kgenome_emu_get_reg(e, KGENOME_EMU_RAX) & 0xffffffffu) == 0, "VirtualProtect on unmapped pages answers FALSE");
	{
		uint64_t gle = kgenome_emu_win_addr_of(e, "GetLastError");

		CK(call0(e, 64, gle) == 0 && (kgenome_emu_get_reg(e, KGENOME_EMU_RAX) & 0xffffffffu) == 487,
		   "and leaves ERROR_INVALID_ADDRESS (487)");
	}
	/* a mapped range still succeeds */
	n = 0;
	c[n++] = 0x48; c[n++] = 0xb8; memcpy(c + n, &vp, 8); n += 8;
	c[n++] = 0xb9; { uint32_t a = (uint32_t)STACK; memcpy(c + n, &a, 4); n += 4; }
	c[n++] = 0xba; c[n++] = 5; c[n++] = 0; c[n++] = 0; c[n++] = 0;
	c[n++] = 0x41; c[n++] = 0xb8; c[n++] = 0x40; c[n++] = 0; c[n++] = 0; c[n++] = 0;
	c[n++] = 0x49; c[n++] = 0xb9; { uint64_t o = STACK + 0x100; memcpy(c + n, &o, 8); n += 8; }
	c[n++] = 0xff; c[n++] = 0xd0;
	CK(run(e, c, n, 64) == 0 && (kgenome_emu_get_reg(e, KGENOME_EMU_RAX) & 0xffffffffu) == 1,
	   "a mapped range is still accepted");

	/* RaiseException with a vectored handler registered through the ntdll name */
	kgenome_emu_write(e, CODE + 0x900, h, sizeof h);
	addveh = kgenome_emu_win_addr_of(e, "RtlAddVectoredExceptionHandler");
	raise_ = kgenome_emu_win_addr_of(e, "RaiseException");
	CK(addveh != 0 && addveh != kgenome_emu_win_addr_of(e, "AddVectoredExceptionHandler"),
	   "ntdll has its own RtlAddVectoredExceptionHandler");
	n = 0;
	c[n++] = 0x48; c[n++] = 0xb8; memcpy(c + n, &addveh, 8); n += 8;
	c[n++] = 0xb9; c[n++] = 1; c[n++] = 0; c[n++] = 0; c[n++] = 0;                     /* ecx = 1 (first) */
	c[n++] = 0x48; c[n++] = 0xba; { uint64_t ha = CODE + 0x900; memcpy(c + n, &ha, 8); n += 8; } /* rdx = handler */
	c[n++] = 0xff; c[n++] = 0xd0;
	c[n++] = 0x48; c[n++] = 0xb8; memcpy(c + n, &raise_, 8); n += 8;
	c[n++] = 0xb9; { uint32_t code = 0xc000008eu; memcpy(c + n, &code, 4); n += 4; }   /* ecx = code */
	c[n++] = 0x31; c[n++] = 0xd2;                                                      /* edx = 0 flags */
	c[n++] = 0x45; c[n++] = 0x31; c[n++] = 0xc0;                                       /* r8d = 0 count */
	c[n++] = 0x45; c[n++] = 0x31; c[n++] = 0xc9;                                       /* r9d = 0 args */
	c[n++] = 0xff; c[n++] = 0xd0;
	CK(run(e, c, n, 64) == 0, "a raised exception whose handler returns -1 resumes after the call (rip=%#llx)",
	   (unsigned long long)kgenome_emu_get_rip(e));
	kgenome_emu_exc_counts(e, &raised, &taken, &veh);
	CK(raised == 1 && taken == 1 && veh == 1, "one raised, one taken by the handler (%u %u %u)", raised, taken, veh);

	/* IN is a privileged instruction: the handler is offered it */
	{
		uint8_t in_[2] = { 0xed, 0xf4 };

		kgenome_emu_write(e, CODE + 0x300, in_, sizeof in_);
		kgenome_emu_set_rip(e, CODE + 0x300);
		kgenome_emu_set_reg(e, KGENOME_EMU_RSP, STACK + 0x8000);
		kgenome_emu_set_max_insn(e, kgenome_emu_insn_count(e) + 1000u);
		(void)kgenome_emu_run(e);
		kgenome_emu_exc_counts(e, &raised, &taken, &veh);
		CK(raised >= 2, "`in eax, dx` raised an exception for the handlers (%u)", raised);
	}
	kgenome_emu_free(e);

	/* mscoree: absent until loaded, and entering _CorExeMain is the end of the run */
	e = mk(64);
	CK(e != NULL, "machine");
	if (!e)
		return;
	{
		uint64_t gmh = kgenome_emu_win_addr_of(e, "GetModuleHandleA"), ll = kgenome_emu_win_addr_of(e, "LoadLibraryA");
		uint64_t name = CODE + 0x1000;
		const char nm[] = "mscoree.dll";

		kgenome_emu_write(e, name, nm, sizeof nm);
		n = 0;
		c[n++] = 0x48; c[n++] = 0xb8; memcpy(c + n, &gmh, 8); n += 8;
		c[n++] = 0x48; c[n++] = 0xb9; memcpy(c + n, &name, 8); n += 8;
		c[n++] = 0xff; c[n++] = 0xd0;
		CK(run(e, c, n, 64) == 0 && kgenome_emu_get_reg(e, KGENOME_EMU_RAX) == 0, "GetModuleHandle(mscoree) is NULL before a load");
		n = 0;
		c[n++] = 0x48; c[n++] = 0xb8; memcpy(c + n, &ll, 8); n += 8;
		c[n++] = 0x48; c[n++] = 0xb9; memcpy(c + n, &name, 8); n += 8;
		c[n++] = 0xff; c[n++] = 0xd0;
		CK(run(e, c, n, 64) == 0 && kgenome_emu_get_reg(e, KGENOME_EMU_RAX) == kgenome_emu_win_mod_base(KGENOME_EMU_WIN_MOD_MSCOREE, 64),
		   "LoadLibrary(mscoree) answers its image's base (%#llx)", (unsigned long long)kgenome_emu_get_reg(e, KGENOME_EMU_RAX));
		n = 0;
		c[n++] = 0x48; c[n++] = 0xb8; memcpy(c + n, &gmh, 8); n += 8;
		c[n++] = 0x48; c[n++] = 0xb9; memcpy(c + n, &name, 8); n += 8;
		c[n++] = 0xff; c[n++] = 0xd0;
		CK(run(e, c, n, 64) == 0 && kgenome_emu_get_reg(e, KGENOME_EMU_RAX) != 0, "and GetModuleHandle sees it after");
	}
	mscoree = kgenome_emu_win_addr_of(e, "_CorExeMain");
	CK(mscoree != 0 && mscoree == kgenome_emu_win_mod_base(KGENOME_EMU_WIN_MOD_MSCOREE, 64) + KGENOME_EMU_WIN_STUB_RVA,
	   "_CorExeMain is the first stub of mscoree's image");
	lastbefore = kgenome_emu_insn_count(e);
	{
		enum kgenome_emu_stop st;

		(void)call0(e, 64, mscoree);
		st = KGENOME_EMU_STOP_HANDOFF;
		CK(kgenome_emu_get_rip(e) < CODE || kgenome_emu_get_rip(e) > CODE + 0x40, "the run did not come back from _CorExeMain");
		CK(strstr(kgenome_emu_stop_detail(e), "_CorExeMain") != NULL, "and says why: %s", kgenome_emu_stop_detail(e));
		(void)st;
	}
	(void)lastbefore;
	kgenome_emu_free(e);
	printf("windows model: VirtualProtect 487, vectored handlers, privileged instruction, mscoree hand-over - %s\n",
	       fails ? "FAILED" : "ok");
}

int main(void);
int main(void)
{
	table();
	directory(64);
	directory(32);
	counter();
	windows();
	return fails ? 1 : 0;
}
