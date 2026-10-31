/*
 * engine3_bare - work nothing can read is not done (BE-4, BE-6), and the pack that CAN read it still gets it.
 *
 * A pack with no detector module and no diagnose (the bare pack of a measurement, a host that loaded only unpackers) was charged
 * for two things nobody could read: the normalised view of every PE or ELF that holds a UTF-16 run (BE-4: 66% of the Ir of the
 * binary corpus then), and the emulator run that names what a PE resolves for itself (BE-6: 13.9%). One synthetic PE carries
 * both triggers - a PEB read followed by a load of PEB.Ldr in its entry code, and a 4 KiB .data section of UTF-16 text - and is
 * scanned with the bare pack and with the test pack (which has detectors and diagnoses).
 *
 *   bare pack:  one object (no view), and the interpreter ran for zero instructions
 *   test pack:  two objects (the view is there), so the gate did not take the view away from a pack that reads it
 *   bare pack + kof_scan_option.reader: two objects (a tool that looks at the object is a reader of the view)
 *
 * Why the old tests missed it: (c) the normaliser tests assert the view's CONTENT with a pack that has rules, and nothing asked
 * what a pack with none costs; the bare pack was only ever a loader test.
 */
#define _GNU_SOURCE
#include "hostile_engine.h"
#include <dirent.h>

static void put16(uint8_t *p, unsigned v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); }
static void put32(uint8_t *p, unsigned v) { put16(p, v & 0xffffu); put16(p + 2, v >> 16); }

/* PE32, two sections: .text (0x200 raw, R-X) with the PEB walk, .data (0x1000 raw, RW-) with UTF-16 text. */
static size_t make_pe(uint8_t *f, size_t cap)
{
	static const uint8_t code[] = { 0x64, 0xA1, 0x30, 0, 0, 0,  0x8B, 0x40, 0x0C,  0xB9, 0xFF, 0xFF, 0xFF, 0x7F,  0x49,  0x75, 0xFD,  0xC3 };
	const size_t n = 0x200u + 0x200u + 0x1000u;
	size_t i;
	uint8_t *p, *opt, *s;

	if (cap < n)
		return 0;
	memset(f, 0, n);
	memcpy(f, "MZ", 2);
	put32(f + 0x3c, 0x40);
	p = f + 0x40;
	memcpy(p, "PE\0\0", 4);
	put16(p + 4, 0x14c); put16(p + 6, 2);              /* i386, two sections */
	put16(p + 20, 0xE0); put16(p + 22, 0x102);         /* optional header size, EXECUTABLE | 32BIT */
	opt = p + 24;
	put16(opt, 0x10b);
	put32(opt + 4, 0x200); put32(opt + 16, 0x1000);    /* size of code, entry rva */
	put32(opt + 20, 0x1000); put32(opt + 28, 0x400000);/* base of code, image base */
	put32(opt + 32, 0x1000); put32(opt + 36, 0x200);   /* section alignment, file alignment */
	put16(opt + 40, 4); put16(opt + 48, 4);
	put32(opt + 56, 0x3000); put32(opt + 60, 0x200);   /* size of image, size of headers */
	put16(opt + 68, 3);                                /* console */
	put32(opt + 72, 0x100000); put32(opt + 76, 0x1000);
	put32(opt + 80, 0x100000); put32(opt + 84, 0x1000);
	put32(opt + 92, 16);
	s = opt + 0xE0;
	memcpy(s, ".text", 5);
	put32(s + 8, 0x1000); put32(s + 12, 0x1000); put32(s + 16, 0x200); put32(s + 20, 0x200); put32(s + 36, 0x60000020u);
	s += 40;
	memcpy(s, ".data", 5);
	put32(s + 8, 0x1000); put32(s + 12, 0x2000); put32(s + 16, 0x1000); put32(s + 20, 0x400); put32(s + 36, 0xC0000040u);
	memcpy(f + 0x200, code, sizeof code);
	for (i = 0; i < 0x400; i += 2) {                   /* "kofeng normaliser canary text " in UTF-16LE, repeated */
		static const char t[] = "kofeng normaliser canary text ";

		f[0x400 + i] = (uint8_t)t[(i / 2) % (sizeof t - 1)];
	}
	return n;
}

struct got { unsigned objects; };

static int on_obj(const char *name, const void *b, uint64_t len, const struct kof_result *res, void *u)
{
	(void)name; (void)b; (void)len; (void)res;
	((struct got *)u)->objects++;
	return 0;
}

static int scan_with(const char *db, struct got *g, uint64_t *emu, int report)
{
	uint8_t f[0x2000];
	size_t n = make_pe(f, sizeof f);
	kof_engine *e = keng_open(db);
	kof_scanner *sc = e ? kscan_new(e) : NULL;
	struct kof_scan_option o = he_opt();

	o.reader = report;
	memset(g, 0, sizeof *g);
	if (!sc) {
		printf("  engine3_bare: cannot open %s (run from the repository root after make)\n", db);
		return 9;
	}
	(void)kscan_bytes(sc, f, n, "bare.exe", &o, on_obj, g);
	*emu = kscan_stats(sc)->emu_insn;
	kscan_free(sc);
	keng_close(e);
	return n ? 0 : 9;
}

/*
 * THE BARE PACK, made here: the release database with its diagnose packs left out. The release database holds
 * whatever the tree's bases/diagnoses held when it was built (the reader's own Generate output is one), so
 * "build/release/databases" is bare only while nobody has written a diagnose - the test said so for a
 * tree that had none and failed for the first one that had. A pack with only unpackers is what is meant.
 */
static int make_bare(char *dir, size_t cap)
{
	const char *src = "build/release/databases";
	DIR *d = opendir(src);
	struct dirent *de;
	int n = 0;

	snprintf(dir, cap, "build/kof_engine3_bare_XXXXXX");
	if (!d || !mkdtemp(dir))
		return 0;
	while ((de = readdir(d)) != NULL) {
		char a[512], b[512];
		FILE *in, *out;
		char buf[65536];
		size_t k;

		if (de->d_name[0] == '.' || !strncmp(de->d_name, "diag-", 5))
			continue;
		snprintf(a, sizeof a, "%s/%s", src, de->d_name);
		snprintf(b, sizeof b, "%s/%s", dir, de->d_name);
		in = fopen(a, "rb");
		out = in ? fopen(b, "wb") : NULL;
		while (out && (k = fread(buf, 1, sizeof buf, in)) > 0)
			fwrite(buf, 1, k, out);
		if (in)
			fclose(in);
		if (out) {
			fclose(out);
			n++;
		}
	}
	closedir(d);
	return n;
}

static void rm_bare(const char *dir)
{
	DIR *d = opendir(dir);
	struct dirent *de;

	while (d && (de = readdir(d)) != NULL) {
		char b[512];

		if (de->d_name[0] == '.')
			continue;
		snprintf(b, sizeof b, "%s/%s", dir, de->d_name);
		unlink(b);
	}
	if (d)
		closedir(d);
	rmdir(dir);
}

static int run(void *unused)
{
	struct got bare, full, shown;
	uint64_t emu_bare = 0, emu_full = 0, emu_shown = 0;

	char bd[128];
	int bad;

	(void)unused;
	if (!make_bare(bd, sizeof bd)) {
		printf("  engine3_bare: cannot make the bare pack (run from the repository root after make)\n");
		return 9;
	}
	bad = scan_with(bd, &bare, &emu_bare, 0) || scan_with("build/test/databases-sigs", &full, &emu_full, 0) ||
	      scan_with(bd, &shown, &emu_shown, 1);
	rm_bare(bd);
	if (bad)
		return 9;
	printf("  bare pack: %u object(s), %llu emulated instruction(s); test pack: %u object(s), %llu\n", bare.objects, (unsigned long long)emu_bare, full.objects,
	       (unsigned long long)emu_full);
	CK(bare.objects == 1u, "bare pack: a view was made for a pack that has nothing to read it (%u objects) (BE-4)", bare.objects);
	CK(emu_bare == 0, "bare pack: the API-resolution run executed %llu instructions for a pack that has nothing to read it (BE-6)", (unsigned long long)emu_bare);
	CK(full.objects == 2u, "test pack: the view is missing from a pack that reads it (%u objects)", full.objects);
	/* A tool that is a reader (kofviewer, kofexaminer: a person looks at the objects) reads the view whatever the pack holds. */
	CK(shown.objects == 2u, "bare pack, reader: the view is missing for a tool that looks at the object (%u objects)", shown.objects);
	return he_fails != 0 ? 1 : 0;
}

int main(void)
{
	struct he_status st = he_child(run, NULL, 120);

	printf("engine3_bare %s\n", he_how(st));
	return he_ok(st) ? 0 : 1;
}
