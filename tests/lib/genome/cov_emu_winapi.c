/*
 * cov_emu_winapi - the Windows environment of the interpreter, one API at a time.
 *
 * A guest that asks kernel32 something is answered from tables in emu_winapi.c. Each of the 136 APIs of
 * the table is called here the way a guest calls it - a `call` to the stub address in the module image,
 * the arguments in rcx rdx r8 r9 and on the stack (and, for a 32 bit guest, pushed and popped by the stub) -
 * and what comes back, and what was written to the guest's memory, is checked against what Windows documents
 * for the function; where the environment answers something simpler ON PURPOSE (a heap with no free list, a
 * debugger query refused, a file that is never found) the answer it documents is what is asserted. The places
 * where an earlier version differed from a real machine (HeapSize, HeapReAlloc, the string conversions,
 * GetModuleHandle of a library LoadLibrary made) are fixed and asserted for both widths.
 *
 *   TABLE     every name resolves in its own module, argc matches the stub's `ret n`, the trap numbers are
 *             dense, a name is found without regard to case, an API in a module that is not mapped has no
 *             address
 *   LOADER    GetModuleHandle (self, by name, with and without .dll, wide), LoadLibrary (known, unknown,
 *             a name the analysis-evasion list refuses), GetProcAddress (a name, an ordinal, a bad handle),
 *             VirtualAlloc/Protect/Free/Query, the Nt* forms (the arguments arrive by pointer)
 *   PROCESS   ExitProcess/TerminateProcess stop the run, RaiseException is dispatched and bounded, GetLastError
 *             round-trips, the identity values, the vectored handlers, the unhandled-exception filter
 *   HEAP/TLS  one arena: distinct blocks, TLS slots, Interlocked*, critical sections
 *   TEXT      lstrlen/cmp/cmpi/cpy/cat in narrow and wide, the paths the environment invents
 *   NET       the scripted peer: WSAStartup writes 2.2, sockets are distinct, recv answers a 4 byte length
 *             the first time
 *   32 BIT    the same calls with stdcall arguments on the stack
 *
 * The guest is a few instructions; nothing is loaded from a file.
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include <phenotype/emu.h>


static int fails;

#define CK(cond, ...) do { \
	if (!(cond)) { \
		printf("  FAIL %s:%d  ", __FILE__, __LINE__); \
		printf(__VA_ARGS__); \
		printf("\n"); \
		fails++; \
	} \
} while (0)

#define CODE   0x400000ull
#define DATA   0x600000ull
#define STACK  0x7ff00000ull
#define IMAGE  0x140000000ull

static struct kgenome_emu *mk(unsigned bits)
{
	struct kgenome_emu_cfg cfg;
	struct kgenome_emu *e;
	unsigned i, n = kgenome_emu_win_api_count();

	memset(&cfg, 0, sizeof cfg);
	cfg.bits = bits;
	cfg.max_insn = 1000000;
	e = kgenome_emu_new(&cfg);
	if (!e)
		return NULL;
	for (i = 0; i < kgenome_emu_win_mod_count(); i++)
		kgenome_emu_win_set_module(e, i, kgenome_emu_win_mod_base(i, bits));
	kgenome_emu_win_setup(e, bits == 32 ? 0x400000ull : IMAGE);
	kgenome_emu_win_set_heap(e, 0x1000000ull);
	/* the module images: one page of stubs each, as emu_unpack_pe_module.c writes them */
	for (i = 0; i < kgenome_emu_win_mod_count(); i++)
		kgenome_emu_map(e, kgenome_emu_win_mod_base(i, bits) + KGENOME_EMU_WIN_STUB_RVA, NULL, 0,
				0x8000, KGENOME_EMU_R | KGENOME_EMU_W | KGENOME_EMU_X);
	for (i = 0; i < n; i++) {
		uint64_t a = kgenome_emu_win_addr_of(e, kgenome_emu_win_api_name(i));
		uint8_t stub[16];
		unsigned argc = kgenome_emu_win_api_argc(i);
		uint32_t trap = kgenome_emu_win_api_trap(i);

		if (!a)
			continue;
		memset(stub, 0xcc, sizeof stub);
		stub[0] = 0xb8;
		memcpy(stub + 1, &trap, 4);
		if (bits == 32) {
			stub[5] = 0xcd; stub[6] = 0x80;
			if (argc) {
				uint16_t pop = (uint16_t)(argc * 4u);

				stub[7] = 0xc2;
				memcpy(stub + 8, &pop, 2);
			} else {
				stub[7] = 0xc3;
			}
		} else {
			stub[5] = 0x0f; stub[6] = 0x05; stub[7] = 0xc3;
		}
		kgenome_emu_write(e, a, stub, sizeof stub);
	}
	kgenome_emu_map(e, CODE, NULL, 0, 0x2000, KGENOME_EMU_R | KGENOME_EMU_W | KGENOME_EMU_X);
	kgenome_emu_map(e, DATA, NULL, 0, 0x10000, KGENOME_EMU_R | KGENOME_EMU_W);
	kgenome_emu_map(e, STACK, NULL, 0, 0x10000, KGENOME_EMU_R | KGENOME_EMU_W);
	return e;
}

struct callres {
	uint64_t              ret;
	enum kgenome_emu_stop stop;
	int                   done;     /* came back to the HLT */
};

/* call API `name` with up to eight arguments */
static struct callres call(struct kgenome_emu *e, unsigned bits, const char *name, uint64_t a0, uint64_t a1,
			   uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5, uint64_t a6, uint64_t a7)
{
	struct callres r;
	uint64_t stub = kgenome_emu_win_addr_of(e, name);
	uint64_t args[8] = { a0, a1, a2, a3, a4, a5, a6, a7 };
	uint8_t code[256];
	unsigned n = 0, k, argc = 8;
	uint64_t rsp = STACK + 0x8000;

	memset(&r, 0, sizeof r);
	for (k = 0; k < kgenome_emu_win_api_count(); k++)
		if (!strcmp(kgenome_emu_win_api_name(k), name))
			argc = kgenome_emu_win_api_argc(k);
	CK(stub != 0, "the stub of %s exists", name);
	if (!stub)
		return r;
	if (bits == 32) {
		for (k = argc; k > 0; k--) {
			uint32_t v = (uint32_t)args[k - 1];

			code[n++] = 0x68;
			memcpy(code + n, &v, 4);
			n += 4;
		}
		code[n++] = 0xb8;
		{
			uint32_t s = (uint32_t)stub;

			memcpy(code + n, &s, 4);
			n += 4;
		}
		code[n++] = 0xff; code[n++] = 0xd0;           /* call eax */
		code[n++] = 0xf4;
	} else {
		/* the first four in registers, the rest in the caller's frame above a 32 byte shadow space */
		static const uint8_t mv[4][2] = { { 0x48, 0xb9 }, { 0x48, 0xba }, { 0x49, 0xb8 }, { 0x49, 0xb9 } };

		for (k = 0; k < 4; k++) {
			code[n++] = mv[k][0];
			code[n++] = mv[k][1];
			memcpy(code + n, &args[k], 8);
			n += 8;
		}
		for (k = 4; k < 8; k++)
			kgenome_emu_write(e, rsp + 0x20u + 8u * (k - 4u), &args[k], 8);
		code[n++] = 0x48; code[n++] = 0xb8;
		memcpy(code + n, &stub, 8);
		n += 8;
		code[n++] = 0xff; code[n++] = 0xd0;           /* call rax */
		code[n++] = 0xf4;
	}
	kgenome_emu_write(e, CODE, code, n);
	kgenome_emu_set_rip(e, CODE);
	kgenome_emu_set_reg(e, KGENOME_EMU_RSP, rsp);
	r.stop = kgenome_emu_run(e);
	r.done = kgenome_emu_get_rip(e) == CODE + n - 1u;
	r.ret = kgenome_emu_get_reg(e, KGENOME_EMU_RAX);
	if (bits == 32)
		r.ret &= 0xffffffffull;
	return r;
}

#define C0(e, b, nm)               call((e), (b), (nm), 0, 0, 0, 0, 0, 0, 0, 0)
#define C1(e, b, nm, x)            call((e), (b), (nm), (x), 0, 0, 0, 0, 0, 0, 0)
#define C2(e, b, nm, x, y)         call((e), (b), (nm), (x), (y), 0, 0, 0, 0, 0, 0)
#define C3(e, b, nm, x, y, z)      call((e), (b), (nm), (x), (y), (z), 0, 0, 0, 0, 0)
#define C4(e, b, nm, x, y, z, w)   call((e), (b), (nm), (x), (y), (z), (w), 0, 0, 0, 0)

static void put(struct kgenome_emu *e, uint64_t va, const void *p, unsigned n)
{
	kgenome_emu_write(e, va, p, n);
}

static void puts_(struct kgenome_emu *e, uint64_t va, const char *s)
{
	put(e, va, s, (unsigned)strlen(s) + 1u);
}

static void putw16(struct kgenome_emu *e, uint64_t va, const char *s)
{
	unsigned i;

	for (i = 0;; i++) {
		uint16_t c = (uint8_t)s[i];

		put(e, va + 2u * i, &c, 2);
		if (!c)
			break;
	}
}

static uint64_t get(struct kgenome_emu *e, uint64_t va, unsigned n)
{
	uint64_t v = 0;

	if (!kgenome_emu_read(e, va, &v, n))
		return 0xdeadbeefdeadbeefull;
	return v;
}

static void gets_(struct kgenome_emu *e, uint64_t va, char *out, unsigned cap)
{
	unsigned i;

	for (i = 0; i + 1 < cap; i++) {
		uint8_t c = 0;

		kgenome_emu_read(e, va + i, &c, 1);
		out[i] = (char)c;
		if (!c)
			return;
	}
	out[cap - 1] = 0;
}

/* ---- the table ----------------------------------------------------------------------------- */

static void t_table(void)
{
	unsigned n = kgenome_emu_win_api_count(), i;
	struct kgenome_emu *e = mk(64);
	unsigned per_mod[16] = { 0 };

	CK(n == 140, "the table has %u APIs", n);
	CK(kgenome_emu_win_mod_count() == KGENOME_EMU_WIN_MOD_COUNT, "module count %u", kgenome_emu_win_mod_count());
	for (i = 0; i < n; i++) {
		const char *nm = kgenome_emu_win_api_name(i);
		unsigned m = kgenome_emu_win_api_mod(i);
		uint64_t a;

		CK(nm && *nm, "api %u has a name", i);
		CK(kgenome_emu_win_api_trap(i) == 0x57494e00u + i, "api %u trap %#x", i, kgenome_emu_win_api_trap(i));
		CK(m < kgenome_emu_win_mod_count(), "api %s module %u", nm, m);
		CK(kgenome_emu_win_api_argc(i) <= 8, "api %s argc %u", nm, kgenome_emu_win_api_argc(i));
		if (m < 16)
			CK(kgenome_emu_win_api_slot(i) == per_mod[m]++, "api %s slot is dense in its module (%u)", nm,
			   kgenome_emu_win_api_slot(i));
		if (e) {
			a = kgenome_emu_win_addr_of(e, nm);
			CK(a == kgenome_emu_win_mod_base(m, 64) + KGENOME_EMU_WIN_STUB_RVA +
				(uint64_t)kgenome_emu_win_api_slot(i) * KGENOME_EMU_WIN_STUB, "%s resolves into its module", nm);
			CK(kgenome_emu_win_resolve(e, nm) == a, "%s: resolve agrees with addr_of", nm);
		}
	}
	CK(kgenome_emu_win_api_name(n) == NULL || kgenome_emu_win_api_name(n)[0] == 0, "no name past the end");
	CK(kgenome_emu_win_mod_name(KGENOME_EMU_WIN_MOD_K32) != NULL && !strcmp(kgenome_emu_win_mod_name(0), "kernel32.dll"),
	   "module 0 is kernel32");
	CK(kgenome_emu_win_mod_base(0, 32) != kgenome_emu_win_mod_base(0, 64), "the two widths have their own bases");
	if (e)
		kgenome_emu_free(e);
}

/* ---- the loader ----------------------------------------------------------------------------- */

static void t_loader(unsigned bits)
{
	struct kgenome_emu *e = mk(bits);
	struct callres r;
	uint64_t k32 = kgenome_emu_win_mod_base(KGENOME_EMU_WIN_MOD_K32, bits), p, q;

	if (!e) {
		CK(0, "emulator");
		return;
	}
	puts_(e, DATA, "kernel32.dll");
	puts_(e, DATA + 0x40, "KERNEL32");
	puts_(e, DATA + 0x80, "nosuchlib.dll");
	puts_(e, DATA + 0xc0, "ntdll.dll");
	putw16(e, DATA + 0x100, "Kernel32.DLL");
	puts_(e, DATA + 0x140, "SbieDll.dll");
	puts_(e, DATA + 0x180, "GetTickCount");
	puts_(e, DATA + 0x1c0, "NoSuchExportAnywhere");
	puts_(e, DATA + 0x200, "x");

	r = C1(e, bits, "GetModuleHandleA", 0);
	CK(r.done && r.ret == (bits == 32 ? 0x400000ull : IMAGE), "GetModuleHandle(NULL) is the image base, %#llx", (unsigned long long)r.ret);
	r = C1(e, bits, "GetModuleHandleA", DATA);
	CK(r.ret == k32, "kernel32.dll by name, %#llx vs %#llx", (unsigned long long)r.ret, (unsigned long long)k32);
	r = C1(e, bits, "GetModuleHandleA", DATA + 0x40);
	CK(r.ret == k32, "kernel32 without the extension and in capitals");
	r = C1(e, bits, "GetModuleHandleW", DATA + 0x100);
	CK(r.ret == k32, "the wide form");
	r = C1(e, bits, "GetModuleHandleA", DATA + 0x80);
	CK(r.done && r.ret == 0, "a library that is not loaded is not loaded");
	r = C1(e, bits, "GetModuleHandleA", DATA + 0xc0);
	CK(r.ret == kgenome_emu_win_mod_base(KGENOME_EMU_WIN_MOD_NTDLL, bits) && r.ret != 0, "ntdll has its own image");

	r = C1(e, bits, "LoadLibraryA", DATA);
	CK(r.ret == k32, "LoadLibrary of a loaded module is its base");
	r = C1(e, bits, "LoadLibraryA", DATA + 0x80);
	p = r.ret;
	CK(r.done && p != 0 && p != k32, "an unknown library still has a handle (a name the analysis does not carry)");
	r = C1(e, bits, "LoadLibraryA", DATA + 0x80);
	CK(r.ret == p, "and the same one the second time");
	r = C1(e, bits, "GetModuleHandleA", DATA + 0x80);
	CK(r.ret == p, "GetModuleHandle finds a library LoadLibrary has just made a handle for");
	r = C1(e, bits, "LoadLibraryA", DATA + 0x140);
	CK(r.done && r.ret == 0, "a library whose presence gives the analysis away is refused");
	r = C1(e, bits, "LoadLibraryW", DATA + 0x100);
	CK(r.ret == k32, "LoadLibraryW");
	r = C1(e, bits, "FreeLibrary", p);
	CK(r.ret == 1, "FreeLibrary");

	r = C2(e, bits, "GetProcAddress", k32, DATA + 0x180);
	q = kgenome_emu_win_addr_of(e, "GetTickCount");
	CK(r.ret == q && q != 0, "GetProcAddress of an export is the stub address");
	r = C2(e, bits, "GetProcAddress", k32, DATA + 0x1c0);
	CK(r.done && r.ret != 0 && r.ret < 0x10000,
	   "a plausible name the table lacks gets a miss thunk in the null page, %#llx", (unsigned long long)r.ret);
	r = C2(e, bits, "GetProcAddress", k32, 5);
	CK(r.done && r.ret == 0, "an ordinal into a module that has an image: nothing to look up");
	r = C2(e, bits, "GetProcAddress", 0x12345000, DATA + 0x180);
	CK(r.done && r.ret == 0, "a handle nobody was given");
	r = C2(e, bits, "GetProcAddress", p, DATA + 0x180);
	CK(r.ret == kgenome_emu_win_resolve(e, "GetTickCount") || r.ret != 0, "a fake library resolves a name to a thunk");
	r = C2(e, bits, "GetProcAddress", p, 7);
	CK(r.done && r.ret != 0, "an ordinal into a fake library is a miss thunk");
	r = C2(e, bits, "GetProcAddress", k32, DATA + 0x200);
	CK(r.done && r.ret == 0, "an implausible name (one letter) is not an export");

	kgenome_emu_free(e);
}

static void t_vm(unsigned bits)
{
	struct kgenome_emu *e = mk(bits);
	struct callres r;
	uint64_t a, b, k32 = kgenome_emu_win_mod_base(KGENOME_EMU_WIN_MOD_K32, bits);
	uint8_t z[64];
	unsigned i, zero = 1;

	if (!e) {
		CK(0, "emulator");
		return;
	}
	r = C4(e, bits, "VirtualAlloc", 0, 0x1800, 0x3000, 4);
	a = r.ret;
	CK(r.done && a && !(a & 0xfff), "VirtualAlloc returns a page aligned block, %#llx", (unsigned long long)a);
	kgenome_emu_read(e, a + 0x17f0, z, 16);
	for (i = 0; i < 16; i++)
		zero &= z[i] == 0;
	CK(zero, "the new memory is zero");
	CK(kgenome_emu_write(e, a + 0x17f8, "abcdefgh", 8), "and is writable to its last byte");
	r = C4(e, bits, "VirtualAlloc", 0, 0x1000, 0x3000, 4);
	b = r.ret;
	CK(b && b != a && (b >= a + 0x2000 || b + 0x1000 <= a), "the next block is elsewhere (%#llx)", (unsigned long long)b);
	r = C4(e, bits, "VirtualAlloc", 0, 0, 0x3000, 4);
	CK(r.done && r.ret == 0, "a zero size is refused");
	r = C4(e, bits, "VirtualAlloc", 0, 0x7fffffffffffffffull, 0x3000, 4);
	CK(r.done && r.ret == 0, "a size no arena has is refused, not wrapped");
	r = C4(e, bits, "VirtualAlloc", k32 + 0x1000, 0x1000, 0x3000, 0x40);
	CK(r.done && r.ret == 0, "Windows refuses an explicit address inside a mapped image: so does this");
	r = C4(e, bits, "VirtualAlloc", 0x20000000, 0x2000, 0x3000, 0x40);
	CK(r.done && r.ret == 0x20000000, "an explicit free address is granted as asked");
	CK(kgenome_emu_write(e, 0x20000000 + 0x1ff8, "12345678", 8), "and is there");

	r = C3(e, bits, "VirtualFree", a, 0, 0x8000);
	CK(r.ret == 1, "VirtualFree answers TRUE");
	r = C4(e, bits, "VirtualProtect", a, 0x1000, 0x40, DATA + 0x300);
	CK(r.ret == 1 && get(e, DATA + 0x300, 4) == 0x40, "VirtualProtect reports TRUE and writes an old protection");
	r = C4(e, bits, "VirtualProtect", a, 0, 0x40, DATA + 0x300);
	CK(r.done && r.ret == 0, "a zero length is refused");
	r = C4(e, bits, "VirtualProtect", a, 0x1000, 0x40, 0);
	CK(r.ret == 1, "the old-protection pointer is optional");

	r = C3(e, bits, "VirtualQuery", a + 0x123, DATA + 0x400, bits == 32 ? 28 : 48);
	CK(r.ret == (bits == 32 ? 28u : 48u), "VirtualQuery returns the size of the record");
	if (bits == 64) {
		CK(get(e, DATA + 0x400, 8) == a, "BaseAddress is the page of the query");
		CK(get(e, DATA + 0x400 + 24, 8) == 0x1000, "RegionSize is a page");
		CK(get(e, DATA + 0x400 + 32, 4) == 0x1000, "State is MEM_COMMIT");
	} else {
		CK(get(e, DATA + 0x400, 4) == (a & 0xfffff000u), "BaseAddress (32 bit)");
		CK(get(e, DATA + 0x400 + 16, 4) == 0x1000, "State is MEM_COMMIT (32 bit)");
	}
	r = C3(e, bits, "VirtualQuery", a, 0, 48);
	CK(r.done && r.ret == 0, "no output buffer: nothing");

	r = C1(e, bits, "GetSystemInfo", DATA + 0x500);
	CK(r.done && get(e, DATA + 0x504, 4) == 0x1000, "dwPageSize is 4096");
	CK(get(e, DATA + 0x500 + (bits == 32 ? 20 : 32), 4) == 1, "one processor");

	/* the Nt forms take pointers */
	{
		uint64_t base = 0, sz = 0x3000;

		put(e, DATA + 0x600, &base, bits == 32 ? 4 : 8);
		put(e, DATA + 0x640, &sz, bits == 32 ? 4 : 8);
		r = call(e, bits, "NtAllocateVirtualMemory", (uint64_t)-1, DATA + 0x600, 0, DATA + 0x640, 0x3000, 4, 0, 0);
		CK(r.done && r.ret == 0, "NtAllocateVirtualMemory succeeds (%#llx)", (unsigned long long)r.ret);
		base = get(e, DATA + 0x600, bits == 32 ? 4 : 8);
		CK(base && !(base & 0xfff) && kgenome_emu_write(e, base + 0x2ff8, "abcdefgh", 8), "and the base it wrote is usable");
		sz = 0;
		put(e, DATA + 0x640, &sz, bits == 32 ? 4 : 8);
		r = call(e, bits, "NtAllocateVirtualMemory", (uint64_t)-1, DATA + 0x600, 0, DATA + 0x640, 0x3000, 4, 0, 0);
		CK(r.done && r.ret == 0xc0000017ull, "a zero region: STATUS_NO_MEMORY");
		sz = 0x1000;
		put(e, DATA + 0x600, &base, bits == 32 ? 4 : 8);
		put(e, DATA + 0x640, &sz, bits == 32 ? 4 : 8);
		r = call(e, bits, "NtProtectVirtualMemory", (uint64_t)-1, DATA + 0x600, DATA + 0x640, 0x40, DATA + 0x680, 0, 0, 0);
		CK(r.done && r.ret == 0, "NtProtectVirtualMemory is STATUS_SUCCESS");
	}
	kgenome_emu_free(e);
}

/* ---- the process --------------------------------------------------------------------------- */

static void t_process(unsigned bits)
{
	struct kgenome_emu *e = mk(bits);
	struct callres r;
	uint64_t t1, t2, h1, h2;
	uint32_t raised = 0, handled = 0, nveh = 0;

	if (!e) {
		CK(0, "emulator");
		return;
	}
	r = C0(e, bits, "GetCurrentProcess");
	CK(r.ret == (bits == 32 ? 0xffffffffull : ~0ull), "GetCurrentProcess is the pseudo handle -1");
	r = C0(e, bits, "GetCurrentThread");
	CK(r.ret == (bits == 32 ? 0xfffffffeull : ~1ull), "GetCurrentThread is the pseudo handle -2");
	r = C0(e, bits, "IsDebuggerPresent");
	CK(r.ret == 0, "no debugger");
	r = C0(e, bits, "GetVersion");
	CK((r.ret & 0xff) == 10 && ((r.ret >> 8) & 0xff) == 0 && (r.ret >> 16) == 19045, "GetVersion: major in the low byte (%#llx)",
	   (unsigned long long)r.ret);
	r = C0(e, bits, "GetCurrentProcessId");
	CK(r.ret == 0x1000, "pid");
	r = C0(e, bits, "GetCurrentThreadId");
	CK(r.ret == 0x2000, "tid");
	r = C1(e, bits, "SetLastError", 0x57);
	r = C0(e, bits, "GetLastError");
	CK(r.ret == 0x57, "the last error round-trips");
	r = C1(e, bits, "SetLastError", 0);
	r = C0(e, bits, "GetLastError");
	CK(r.ret == 0, "and back to zero");

	r = C0(e, bits, "GetTickCount");
	t1 = r.ret;
	r = C0(e, bits, "GetTickCount");
	t2 = r.ret;
	CK(t2 >= t1, "GetTickCount only moves forward (%llu then %llu)", (unsigned long long)t1, (unsigned long long)t2);
	r = C1(e, bits, "QueryPerformanceFrequency", DATA);
	CK(r.ret == 1 && get(e, DATA, 8) == 1000000, "QueryPerformanceFrequency stores 1 MHz");
	r = C1(e, bits, "QueryPerformanceCounter", DATA + 8);
	t1 = get(e, DATA + 8, 8);
	r = C1(e, bits, "QueryPerformanceCounter", DATA + 8);
	t2 = get(e, DATA + 8, 8);
	CK(r.ret == 1 && t2 >= t1, "the performance counter does not go back");
	r = C1(e, bits, "GetSystemTimeAsFileTime", DATA + 16);
	t1 = get(e, DATA + 16, 8);
	CK(t1 > 0x01d0000000000000ull, "the file time is a date after 2016");
	r = C1(e, bits, "Sleep", 100000);
	CK(r.done && r.ret == 0, "Sleep returns at once");

	/* vectored handlers: first goes first, the handle is the handler, remove says whether it was there */
	r = C2(e, bits, "AddVectoredExceptionHandler", 0, 0x401000);
	h1 = r.ret;
	r = C2(e, bits, "AddVectoredExceptionHandler", 1, 0x402000);
	h2 = r.ret;
	CK(h1 == 0x401000 && h2 == 0x402000, "the handle is the handler");
	r = C2(e, bits, "AddVectoredExceptionHandler", 1, 0);
	CK(r.ret == 0, "a null handler is refused");
	r = C1(e, bits, "RemoveVectoredExceptionHandler", h1);
	CK(r.ret == 1, "remove finds it");
	r = C1(e, bits, "RemoveVectoredExceptionHandler", h1);
	CK(r.ret == 0, "and not twice");
	r = C1(e, bits, "RemoveVectoredExceptionHandler", h2);
	CK(r.ret == 1, "the other");
	{
		unsigned i;
		int full = 0;

		for (i = 0; i < 64; i++) {
			r = C2(e, bits, "AddVectoredExceptionHandler", 0, 0x500000 + 0x10 * i);
			if (!r.ret) {
				full = 1;
				break;
			}
		}
		CK(full && i > 4, "the table of handlers is bounded (%u held)", i);
	}
	r = C1(e, bits, "SetUnhandledExceptionFilter", 0x403000);
	CK(r.ret == 0, "no previous filter");
	r = C1(e, bits, "SetUnhandledExceptionFilter", 0x404000);
	CK(r.ret == 0x403000, "the previous filter is returned");
	r = C1(e, bits, "UnhandledExceptionFilter", 0);
	CK(r.ret == 1, "EXCEPTION_EXECUTE_HANDLER");

	/* the run ends */
	r = C1(e, bits, "ExitProcess", 3);
	CK(r.stop == KGENOME_EMU_STOP_EXIT && !r.done, "ExitProcess ends the run (%s)", kgenome_emu_stop_name(r.stop));
	kgenome_emu_free(e);
	e = mk(bits);
	r = C2(e, bits, "TerminateProcess", (uint64_t)-1, 1);
	CK(r.stop == KGENOME_EMU_STOP_EXIT, "TerminateProcess ends the run (%s)", kgenome_emu_stop_name(r.stop));
	kgenome_emu_free(e);

	/* a raise nobody takes: the run goes on after the call, a bounded number of times, and says how many */
	e = mk(bits);
	{
		unsigned i, carried = 0;

		for (i = 0; i < 100; i++) {
			r = call(e, bits, "RaiseException", 0xc0000094, 0, 0, 0, 0, 0, 0, 0);
			if (r.done)
				carried++;
			else
				break;
		}
		kgenome_emu_exc_counts(e, &raised, &handled, &nveh);
		CK(carried > 0 && carried < 100, "an unhandled raise returns to the guest %u time(s) and then ends the run", carried);
		CK(raised >= carried, "the count of raised exceptions is kept (%u)", raised);
		CK(r.stop == KGENOME_EMU_STOP_EXIT && strstr(kgenome_emu_stop_detail(e), "unhandled raise"),
		   "and the end says why: %s", kgenome_emu_stop_detail(e));
	}
	kgenome_emu_free(e);
}

/* ---- heap, TLS, interlocked, critical sections ------------------------------------------- */

static void t_heap(unsigned bits)
{
	struct kgenome_emu *e = mk(bits);
	struct callres r;
	uint64_t h, a, b, c;
	unsigned i;

	if (!e) {
		CK(0, "emulator");
		return;
	}
	r = C0(e, bits, "GetProcessHeap");
	h = r.ret;
	CK(h == 0x1000000, "GetProcessHeap is the address the host set (%#llx)", (unsigned long long)h);
	r = C3(e, bits, "HeapAlloc", h, 8, 100);
	a = r.ret;
	r = C3(e, bits, "HeapAlloc", h, 8, 100);
	b = r.ret;
	CK(a && b && a != b, "two blocks");
	CK((a > b ? a - b : b - a) >= 100, "that do not overlap");
	CK(get(e, a, 8) == 0 && get(e, a + 92, 4) == 0, "HEAP_ZERO_MEMORY: zero");
	CK(kgenome_emu_write(e, a + 99, "z", 1), "the last byte is writable");
	r = C3(e, bits, "RtlAllocateHeap", h, 0, 4000);
	c = r.ret;
	CK(c && kgenome_emu_write(e, c + 3999, "z", 1), "RtlAllocateHeap is the same allocator");
	r = C3(e, bits, "HeapAlloc", h, 0, 0);
	CK(r.done && r.ret == 0, "a zero size is refused");
	r = C3(e, bits, "HeapFree", h, 0, a);
	CK(r.ret == 1, "HeapFree answers TRUE");
	r = C3(e, bits, "RtlFreeHeap", h, 0, a);
	CK(r.ret == 1, "RtlFreeHeap too");
	r = C3(e, bits, "HeapCreate", 0, 0x1000, 0);
	CK(r.ret == h, "HeapCreate hands out the one heap");
	r = C1(e, bits, "HeapDestroy", h);
	CK(r.ret == 1, "HeapDestroy");

	/* HeapReAlloc copies the old contents into the new block, HeapSize reports what a block was allocated with,
	 * and a block that was freed or never was one is (SIZE_T)-1 */
	{
		char rb[16] = "";
		uint64_t neg = bits == 32 ? 0xffffffffull : ~0ull, nb;

		kgenome_emu_write(e, b, "hello heap", 11);
		r = C4(e, bits, "HeapReAlloc", h, 0, b, 300);
		nb = r.ret;
		kgenome_emu_read(e, nb, rb, 11);
		CK(nb != 0 && nb != b && !strcmp(rb, "hello heap"), "HeapReAlloc keeps the contents of the block it grows (%s)", rb);
		r = C3(e, bits, "HeapSize", h, 0, nb);
		CK(r.ret == 300, "HeapSize of the reallocated block is its new size (%llu)", (unsigned long long)r.ret);
		r = C3(e, bits, "HeapSize", h, 0, b);
		CK(r.ret == neg, "HeapSize of the block HeapReAlloc released is (SIZE_T)-1 (%llx)", (unsigned long long)r.ret);
		r = C3(e, bits, "HeapSize", h, 0, c);
		CK(r.ret == 4000, "HeapSize answers the size the block was allocated with (%llu)", (unsigned long long)r.ret);
		r = C3(e, bits, "HeapSize", h, 0, a);
		CK(r.ret == neg, "HeapSize of a freed block is (SIZE_T)-1 (%llx)", (unsigned long long)r.ret);
		r = C3(e, bits, "HeapSize", h, 0, 0x1234);
		CK(r.ret == neg, "HeapSize of a pointer that is not a block is (SIZE_T)-1");
		/* shrinking keeps only what fits, HEAP_REALLOC_IN_PLACE_ONLY (0x10) refuses to grow */
		r = C4(e, bits, "HeapReAlloc", h, 0, nb, 5);
		kgenome_emu_read(e, r.ret, rb, 6);
		CK(r.ret != 0 && !strncmp(rb, "hello", 5), "HeapReAlloc to a smaller size keeps its start");
		nb = r.ret;
		r = C4(e, bits, "HeapReAlloc", h, 0x10, nb, 50);
		CK(r.done && r.ret == 0, "HEAP_REALLOC_IN_PLACE_ONLY cannot grow a block: NULL");
	}
	r = C2(e, bits, "LocalAlloc", 0x40, 64);
	CK(r.ret && kgenome_emu_write(e, r.ret + 63, "z", 1), "LocalAlloc");
	r = C1(e, bits, "LocalFree", r.ret);
	CK(r.ret == 0, "LocalFree: NULL is success");
	r = C2(e, bits, "GlobalAlloc", 0x40, 64);
	CK(r.ret && kgenome_emu_write(e, r.ret + 63, "z", 1), "GlobalAlloc");
	r = C1(e, bits, "GlobalFree", r.ret);
	CK(r.ret == 0, "GlobalFree");

	/* TLS: slots count up from zero and hold what was put there; past 64 there are none */
	r = C0(e, bits, "TlsAlloc");
	CK(r.ret == 0, "the first TLS index is 0");
	r = C0(e, bits, "TlsAlloc");
	CK(r.ret == 1, "then 1");
	r = C2(e, bits, "TlsSetValue", 1, 0x1234);
	CK(r.ret == 1, "TlsSetValue");
	r = C1(e, bits, "TlsGetValue", 1);
	CK(r.ret == 0x1234, "TlsGetValue returns it");
	r = C1(e, bits, "TlsGetValue", 0);
	CK(r.ret == 0, "an unset slot reads zero");
	r = C1(e, bits, "TlsGetValue", 99);
	CK(r.ret == 0, "an index past the table reads zero");
	r = C2(e, bits, "TlsSetValue", 99, 5);
	CK(r.ret == 1, "a set past the table is accepted and dropped");
	r = C1(e, bits, "TlsFree", 1);
	CK(r.ret == 1, "TlsFree");
	for (i = 2; i < 64; i++)
		r = C0(e, bits, "TlsAlloc");
	r = C0(e, bits, "TlsAlloc");
	CK(r.ret == (bits == 32 ? 0xffffffffull : ~0ull) || r.ret == 0xffffffffull, "no slot past 64: TLS_OUT_OF_INDEXES (%#llx)",
	   (unsigned long long)r.ret);

	/* interlocked */
	{
		uint32_t v = 41;

		put(e, DATA, &v, 4);
		r = C1(e, bits, "InterlockedIncrement", DATA);
		CK(r.ret == 42 && get(e, DATA, 4) == 42, "InterlockedIncrement returns and stores the new value");
		r = C1(e, bits, "InterlockedDecrement", DATA);
		CK(r.ret == 41 && get(e, DATA, 4) == 41, "InterlockedDecrement");
		r = C2(e, bits, "InterlockedExchange", DATA, 7);
		CK(r.ret == 41 && get(e, DATA, 4) == 7, "InterlockedExchange returns the old value, stores the new");
		r = C3(e, bits, "InterlockedCompareExchange", DATA, 9, 7);
		CK(r.ret == 7 && get(e, DATA, 4) == 9, "CompareExchange swaps when equal and returns the initial value");
		r = C3(e, bits, "InterlockedCompareExchange", DATA, 5, 7);
		CK(r.ret == 9 && get(e, DATA, 4) == 9, "and leaves it when not");
		r = C1(e, bits, "InterlockedIncrement", 0x7e000000);
		CK(r.done && r.ret == 0, "an unreadable address answers 0, not a fault (bits %u done %d ret %llx stop %s)", bits, r.done, (unsigned long long)r.ret, kgenome_emu_stop_name(r.stop));
		v = 0xffffffffu;
		put(e, DATA, &v, 4);
		r = C1(e, bits, "InterlockedIncrement", DATA);
		CK(r.ret == 0 && get(e, DATA, 4) == 0, "it wraps at 32 bits");
	}
	r = C1(e, bits, "InitializeCriticalSection", DATA);
	CK(r.done, "InitializeCriticalSection");
	r = C1(e, bits, "EnterCriticalSection", DATA);
	CK(r.done, "EnterCriticalSection");
	r = C1(e, bits, "LeaveCriticalSection", DATA);
	CK(r.done, "LeaveCriticalSection");
	r = C1(e, bits, "DeleteCriticalSection", DATA);
	CK(r.done, "DeleteCriticalSection");
	r = C2(e, bits, "InitializeCriticalSectionAndSpinCount", DATA, 4000);
	CK(r.ret == 1, "InitializeCriticalSectionAndSpinCount is TRUE");
	r = C3(e, bits, "FlushInstructionCache", (uint64_t)-1, DATA, 64);
	CK(r.ret == 1, "FlushInstructionCache");
	kgenome_emu_free(e);
}

/* ---- text ---------------------------------------------------------------------------------- */

static void t_text(unsigned bits)
{
	struct kgenome_emu *e = mk(bits);
	struct callres r;
	char buf[96];

	if (!e) {
		CK(0, "emulator");
		return;
	}
	puts_(e, DATA, "hello");
	puts_(e, DATA + 0x20, "world");
	puts_(e, DATA + 0x40, "HELLO");
	puts_(e, DATA + 0x60, "");
	putw16(e, DATA + 0x80, "wide!");
	r = C1(e, bits, "lstrlenA", DATA);
	CK(r.ret == 5, "lstrlenA");
	r = C1(e, bits, "lstrlenA", DATA + 0x60);
	CK(r.ret == 0, "lstrlenA of the empty string");
	r = C1(e, bits, "lstrlenA", 0x7e000000);
	CK(r.done && r.ret == 0, "lstrlenA of an unreadable pointer");
	r = C1(e, bits, "lstrlenW", DATA + 0x80);
	CK(r.ret == 5, "lstrlenW");
	r = C2(e, bits, "lstrcmpA", DATA, DATA + 0x20);
	CK((int64_t)(int32_t)r.ret < 0, "lstrcmpA: hello < world");
	r = C2(e, bits, "lstrcmpA", DATA + 0x20, DATA);
	CK(r.ret == 1, "lstrcmpA: world > hello");
	r = C2(e, bits, "lstrcmpA", DATA, DATA);
	CK(r.ret == 0, "lstrcmpA: equal");
	r = C2(e, bits, "lstrcmpA", DATA, DATA + 0x40);
	CK(r.ret != 0, "lstrcmpA is case sensitive");
	r = C2(e, bits, "lstrcmpiA", DATA, DATA + 0x40);
	CK(r.ret == 0, "lstrcmpiA is not");
	r = C2(e, bits, "lstrcmpiA", DATA + 0x20, DATA + 0x40);
	CK(r.ret != 0, "lstrcmpiA: different strings differ");
	r = C2(e, bits, "lstrcpyA", DATA + 0x100, DATA);
	gets_(e, DATA + 0x100, buf, sizeof buf);
	CK(r.ret == DATA + 0x100 && !strcmp(buf, "hello"), "lstrcpyA copies and returns the destination (%s)", buf);
	r = C2(e, bits, "lstrcatA", DATA + 0x100, DATA + 0x20);
	gets_(e, DATA + 0x100, buf, sizeof buf);
	CK(r.ret == DATA + 0x100 && !strcmp(buf, "helloworld"), "lstrcatA appends (%s)", buf);
	r = C2(e, bits, "lstrcpyA", DATA + 0x100, 0x7e000000);
	CK(r.done && r.ret == 0, "lstrcpyA from an unreadable pointer: 0 (done %d ret %llx)", r.done, (unsigned long long)r.ret);

	/* the conversions: documented as not done */
	r = call(e, bits, "MultiByteToWideChar", 0, 0, DATA, (uint64_t)-1, DATA + 0x200, 16, 0, 0);
	CK(r.ret == 6 && get(e, DATA + 0x200, 2) == 'h', "MultiByteToWideChar converts \"hello\" and returns the length it wrote, 6 (%llu)", (unsigned long long)r.ret);
	r = call(e, bits, "WideCharToMultiByte", 0, 0, DATA + 0x80, (uint64_t)-1, DATA + 0x300, 16, 0, 0);
	CK(r.ret == 6 && get(e, DATA + 0x300, 1) == 'w', "WideCharToMultiByte converts \"wide!\" and returns the length it wrote, 6 (%llu)", (unsigned long long)r.ret);

	/* the strings the environment invents */
	r = C3(e, bits, "GetModuleFileNameA", 0, DATA + 0x400, 64);
	gets_(e, DATA + 0x400, buf, sizeof buf);
	CK(r.ret == strlen("C:\\Windows\\System32\\image.exe") && !strcmp(buf, "C:\\Windows\\System32\\image.exe"),
	   "GetModuleFileNameA (%s)", buf);
	r = C3(e, bits, "GetModuleFileNameA", 0, DATA + 0x400, 8);
	gets_(e, DATA + 0x400, buf, sizeof buf);
	CK(r.ret == 7 && !strcmp(buf, "C:\\Wind"), "a short buffer: truncated to cap-1 and terminated (%s)", buf);
	r = C3(e, bits, "GetModuleFileNameA", 0, 0, 64);
	CK(r.ret == 0, "no buffer");
	r = C3(e, bits, "GetModuleFileNameW", 0, DATA + 0x500, 64);
	CK(r.ret == 29 && get(e, DATA + 0x500, 2) == 'C', "GetModuleFileNameW");
	r = C0(e, bits, "GetCommandLineA");
	{
		uint64_t cl = r.ret;

		gets_(e, cl, buf, sizeof buf);
		CK(cl && !strcmp(buf, "\"C:\\Windows\\System32\\image.exe\""), "GetCommandLineA is the quoted path (%s)", buf);
		r = C0(e, bits, "GetCommandLineA");
		CK(r.ret == cl, "and the same pointer every time");
		r = C0(e, bits, "GetCommandLineW");
		CK(r.ret && r.ret != cl && get(e, r.ret, 2) == '"', "GetCommandLineW is its own string");
	}
	r = C2(e, bits, "GetSystemDirectoryA", DATA + 0x600, 64);
	gets_(e, DATA + 0x600, buf, sizeof buf);
	CK(r.ret == 19 && !strcmp(buf, "C:\\Windows\\System32"), "GetSystemDirectoryA (%s)", buf);
	r = C2(e, bits, "GetSystemDirectoryA", DATA + 0x600, 4);
	CK(r.ret == 20, "too small a buffer: the size needed, with the terminator");
	r = C2(e, bits, "GetWindowsDirectoryA", DATA + 0x600, 64);
	gets_(e, DATA + 0x600, buf, sizeof buf);
	CK(r.ret == 10 && !strcmp(buf, "C:\\Windows"), "GetWindowsDirectoryA (%s)", buf);
	r = C2(e, bits, "GetTempPathA", 64, DATA + 0x600);
	gets_(e, DATA + 0x600, buf, sizeof buf);
	CK(r.ret == 16 && !strcmp(buf, "C:\\Windows\\Temp\\"), "GetTempPathA takes the length first (%s)", buf);
	r = C1(e, bits, "GetStartupInfoA", DATA + 0x700);
	CK(get(e, DATA + 0x700, 4) == (bits == 32 ? 68u : 104u), "STARTUPINFO.cb");
	r = C1(e, bits, "GetStartupInfoW", DATA + 0x740);
	CK(get(e, DATA + 0x740, 4) == (bits == 32 ? 68u : 104u), "STARTUPINFOW.cb");
	r = C2(e, bits, "GetCPInfo", 1252, DATA + 0x780);
	CK(r.ret == 1 && get(e, DATA + 0x780, 4) == 2, "GetCPInfo: MaxCharSize");
	r = C0(e, bits, "GetACP");
	CK(r.ret == 1252, "GetACP");
	r = C0(e, bits, "GetOEMCP");
	CK(r.ret == 437, "GetOEMCP");
	r = C1(e, bits, "IsValidCodePage", 1252);
	CK(r.ret == 1, "IsValidCodePage");
	r = C1(e, bits, "IsProcessorFeaturePresent", 10);
	CK(r.ret == 0, "no optional processor feature");
	kgenome_emu_free(e);
}

/* ---- handles, files, threads, the Nt layer ------------------------------------------------- */

static void t_misc(unsigned bits)
{
	struct kgenome_emu *e = mk(bits);
	struct callres r;
	uint32_t w;

	if (!e) {
		CK(0, "emulator");
		return;
	}
	puts_(e, DATA, "C:\\x.bin");
	r = C1(e, bits, "GetStdHandle", (uint64_t)-11);
	CK(r.ret == 0x10, "GetStdHandle");
	r = C1(e, bits, "CloseHandle", 0x10);
	CK(r.ret == 1, "CloseHandle");
	r = C1(e, bits, "SetStdHandle", 0x10);
	CK(r.ret == 1, "SetStdHandle");
	r = C1(e, bits, "GetFileAttributesA", DATA);
	CK((uint32_t)r.ret == 0xffffffffu, "no file has attributes: INVALID_FILE_ATTRIBUTES");
	r = call(e, bits, "CreateFileA", DATA, 0x80000000u, 1, 0, 3, 0x80, 0, 0);
	CK((uint32_t)r.ret == 0xffffffffu, "no file opens: INVALID_HANDLE_VALUE");
	r = call(e, bits, "ReadFile", 0x10, DATA + 0x100, 16, DATA + 0x200, 0, 0, 0, 0);
	CK(r.ret == 0, "ReadFile fails");
	r = call(e, bits, "WriteFile", 0x10, DATA + 0x100, 16, DATA + 0x200, 0, 0, 0, 0);
	CK(r.ret == 0, "WriteFile fails");
	r = C4(e, bits, "SetFilePointer", 0x10, 0, 0, 0);
	CK(r.ret == 0, "SetFilePointer");
	r = C2(e, bits, "GetFileSize", 0x10, 0);
	CK((uint32_t)r.ret == 0xffffffffu, "GetFileSize: INVALID_FILE_SIZE");
	r = C1(e, bits, "DeleteFileA", DATA);
	CK(r.ret == 1, "DeleteFileA");
	r = C1(e, bits, "FindClose", 0x10);
	CK(r.ret == 1, "FindClose");
	r = C1(e, bits, "FlushFileBuffers", 0x10);
	CK(r.ret == 1, "FlushFileBuffers");
	r = call(e, bits, "CreateThread", 0, 0, 0x401000, 0, 0, 0, 0, 0);
	CK(r.done && r.ret == 0, "no thread is started: CreateThread fails rather than report one that will never run");
	r = C1(e, bits, "ResumeThread", 0x10);
	CK((uint32_t)r.ret == 0xffffffffu, "ResumeThread fails");
	r = C2(e, bits, "WaitForSingleObject", 0x10, 1000);
	CK(r.ret == 0, "WAIT_OBJECT_0");
	r = C1(e, bits, "OutputDebugStringA", DATA);
	CK(r.done, "OutputDebugStringA");
	r = C1(e, bits, "SetErrorMode", 3);
	CK(r.ret == 0, "SetErrorMode: no previous mode");
	r = C1(e, bits, "SetHandleCount", 20);
	CK(r.ret == 20, "SetHandleCount returns its argument");
	r = C2(e, bits, "SetEnvironmentVariableA", DATA, DATA);
	CK(r.ret == 1, "SetEnvironmentVariableA");
	r = C2(e, bits, "SetConsoleCtrlHandler", 0, 1);
	CK(r.ret == 1, "SetConsoleCtrlHandler");
	r = C1(e, bits, "FreeEnvironmentStringsA", 0);
	CK(r.ret == 1, "FreeEnvironmentStringsA");
	r = C1(e, bits, "DisableThreadLibraryCalls", 0x400000);
	CK(r.ret == 1, "DisableThreadLibraryCalls");
	r = C1(e, bits, "EncodePointer", 0x12345678);
	CK(r.ret == 0x12345678, "EncodePointer is the identity");
	r = C1(e, bits, "DecodePointer", 0x12345678);
	CK(r.ret == 0x12345678, "DecodePointer is the identity");
	r = C2(e, bits, "IsBadReadPtr", DATA, 64);
	CK(r.ret == 0, "IsBadReadPtr of mapped memory");
	r = C2(e, bits, "IsBadReadPtr", 0x7e000000, 4);
	CK(r.ret == 1, "of unmapped memory (%llx)", (unsigned long long)r.ret);
	r = C2(e, bits, "IsBadWritePtr", 0, 4);
	CK(r.ret == 1, "of NULL");
	r = C2(e, bits, "IsBadWritePtr", DATA + 0xfffc, 8);
	CK(r.ret == 1, "of a range that runs off the end of a mapping");
	r = C0(e, bits, "IsUserAnAdmin");
	CK(r.ret == 0, "not an administrator");
	r = C1(e, bits, "CoInitialize", 0);
	CK(r.ret == 0, "CoInitialize: S_OK");
	r = C0(e, bits, "CoUninitialize");
	CK(r.done, "CoUninitialize");
	r = call(e, bits, "SHGetFolderPathA", 0, 0x1a, 0, 0, DATA + 0x300, 0, 0, 0);
	CK((uint32_t)r.ret == 0x80004005u, "SHGetFolderPathA: E_FAIL");
	r = C3(e, bits, "RtlAddFunctionTable", DATA, 1, 0x400000);
	CK(r.ret == 1, "RtlAddFunctionTable");

	/* the Nt layer */
	r = call(e, bits, "NtQueryInformationProcess", (uint64_t)-1, 7, DATA + 0x400, 8, 0, 0, 0, 0);
	CK((uint32_t)r.ret == 0xc0000003u && get(e, DATA + 0x400, 8) == 0, "ProcessDebugPort: refused, the buffer left zero: no debugger is the answer");
	r = C1(e, bits, "RtlGetVersion", DATA + 0x500);
	w = (uint32_t)get(e, DATA + 0x504, 4);
	CK(r.ret == 0 && get(e, DATA + 0x500, 4) == 284 && w == 10 && get(e, DATA + 0x50c, 4) == 19045,
	   "RtlGetVersion: 10.0 build 19045, the same as GetVersion");
	r = C1(e, bits, "RtlGetVersion", 0);
	CK((uint32_t)r.ret == 0xc000000du, "no buffer: STATUS_INVALID_PARAMETER");
	r = call(e, bits, "LdrLoadDll", 0, 0, DATA, DATA + 0x600, 0, 0, 0, 0);
	CK((uint32_t)r.ret == 0xc0000135u, "LdrLoadDll: STATUS_DLL_NOT_FOUND");
	r = call(e, bits, "LdrGetProcedureAddress", 0, DATA, 0, DATA + 0x600, 0, 0, 0, 0);
	CK((uint32_t)r.ret == 0xc0000139u, "LdrGetProcedureAddress: STATUS_ENTRYPOINT_NOT_FOUND");
	kgenome_emu_free(e);
}

/* ---- the scripted peer ---------------------------------------------------------------------- */

static void t_net(unsigned bits)
{
	struct kgenome_emu *e = mk(bits);
	struct callres r;
	uint64_t s1, s2;

	if (!e) {
		CK(0, "emulator");
		return;
	}
	r = C2(e, bits, "WSAStartup", 0x0202, DATA);
	CK(r.ret == 0 && get(e, DATA, 2) == 0x0202, "WSAStartup stores version 2.2 and returns 0");
	r = C2(e, bits, "WSAStartup", 0x0202, 0);
	CK(r.done && r.ret == 0, "with no WSADATA: still 0");
	r = C3(e, bits, "socket", 2, 1, 6);
	s1 = r.ret;
	r = C3(e, bits, "socket", 2, 1, 6);
	s2 = r.ret;
	CK(s1 && s2 && s1 != s2 && s1 != (uint64_t)-1, "two sockets, two handles (%llx %llx)", (unsigned long long)s1,
	   (unsigned long long)s2);
	r = call(e, bits, "WSASocketA", 2, 1, 6, 0, 0, 0, 0, 0);
	CK(r.ret != 0 && r.ret != s1 && r.ret != s2, "WSASocketA");
	r = call(e, bits, "WSASocketW", 2, 1, 6, 0, 0, 0, 0, 0);
	CK(r.ret != 0, "WSASocketW");
	r = C3(e, bits, "accept", s1, 0, 0);
	CK(r.ret != 0, "accept hands out a socket");
	r = C3(e, bits, "connect", s1, DATA, 16);
	CK(r.ret == 0, "connect succeeds");
	r = C3(e, bits, "bind", s1, DATA, 16);
	CK(r.ret == 0, "bind");
	r = C2(e, bits, "listen", s1, 5);
	CK(r.ret == 0, "listen");
	r = C2(e, bits, "shutdown", s1, 2);
	CK(r.ret == 0, "shutdown");
	r = call(e, bits, "setsockopt", s1, 0xffff, 4, DATA, 4, 0, 0, 0);
	CK(r.ret == 0, "setsockopt");
	r = C3(e, bits, "ioctlsocket", s1, 0x8004667e, DATA);
	CK(r.ret == 0, "ioctlsocket");
	r = call(e, bits, "send", s1, DATA, 77, 0, 0, 0, 0, 0);
	CK(r.ret == 77, "send reports every byte sent");
	r = call(e, bits, "sendto", s1, DATA, 55, 0, 0, 0, 0, 0);
	CK(r.ret == 55, "sendto reports every byte sent");

	/* recv: the first read of a socket is a four byte length of 0x1000 (a stager's size prefix); after that, the length asked for */
	put(e, DATA + 0x100, "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa", 8);
	r = call(e, bits, "recv", s1, DATA + 0x100, 4, 0, 0, 0, 0, 0);
	CK(r.ret == 4 && get(e, DATA + 0x100, 4) == 0x1000, "the first recv of 4 bytes is the stage length 0x1000 (%llx)",
	   (unsigned long long)get(e, DATA + 0x100, 4));
	put(e, DATA + 0x100, "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa", 8);
	r = call(e, bits, "recv", s1, DATA + 0x100, 4, 0, 0, 0, 0, 0);
	CK(r.ret == 4 && get(e, DATA + 0x100, 4) == 0xaaaaaaaau, "the second asks for 4 and is told 4, the buffer untouched");
	put(e, DATA + 0x100, "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa", 8);
	r = call(e, bits, "recv", s2, DATA + 0x100, 2, 0, 0, 0, 0, 0);
	CK(r.ret == 2 && get(e, DATA + 0x100, 2) == 0x1000, "another socket has its own first read, of 2 bytes: the low half");
	r = call(e, bits, "recvfrom", s2, DATA + 0x100, 100, 0, 0, 0, 0, 0);
	CK(r.ret == 100, "recvfrom of 100 bytes answers 100");
	r = call(e, bits, "recv", s1, DATA + 0x100, 0, 0, 0, 0, 0, 0);
	CK(r.ret == 0, "a zero length read is 0");
	r = C1(e, bits, "closesocket", s1);
	CK(r.ret == 0, "closesocket");
	r = C0(e, bits, "WSACleanup");
	CK(r.ret == 0, "WSACleanup");
	kgenome_emu_free(e);
}

/* the log of what the guest called, and the miss thunk's behaviour */
static void t_log(void)
{
	struct kgenome_emu *e = mk(64);
	struct callres r;
	struct kgenome_emu_win_event ev;
	uint32_t n, i;
	int saw_tick = 0, saw_last = 0;

	if (!e) {
		CK(0, "emulator");
		return;
	}
	r = C0(e, 64, "GetTickCount");
	r = C1(e, 64, "SetLastError", 5);
	r = C0(e, 64, "GetTickCount");
	n = kgenome_emu_win_event_count(e);
	CK(n >= 2, "the log has %u event(s)", n);
	for (i = 0; i < n; i++)
		if (kgenome_emu_win_event_at(e, i, &ev)) {
			const char *nm = kgenome_emu_win_api_name(ev.api);

			saw_tick |= !strcmp(nm, "GetTickCount");
			saw_last |= !strcmp(nm, "SetLastError") && ev.arg[0] == 5;
		}
	CK(saw_tick && saw_last, "the calls and the first argument are in the log");
	CK(!kgenome_emu_win_event_at(e, n, &ev) && !kgenome_emu_win_event_at(e, 0xffffffffu, &ev), "no event past the end");
	(void)r;
	kgenome_emu_free(e);
}

int main(void)
{
	t_table();
	t_loader(64);
	t_loader(32);
	t_vm(64);
	t_vm(32);
	t_process(64);
	t_process(32);
	t_heap(64);
	t_heap(32);
	t_text(64);
	t_text(32);
	t_misc(64);
	t_misc(32);
	t_net(64);
	t_net(32);
	t_log();
	if (fails) {
		printf("cov_emu_winapi: FAILED (%d)\n", fails);
		return 1;
	}
	printf("cov_emu_winapi: ok\n");
	return 0;
}
