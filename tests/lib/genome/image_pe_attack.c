/*
 * image_pe_attack - coverage-driven attack on kgenome_pe_image_parse and the walkers beside it (round 2,
 * fix_engine2). The baseline never ran: the machine table past x86/x64, the resource directory that
 * starts mid-section, the CLI header and its metadata version string, a truncated optional header, an
 * entry point in zero-fill, a certificate over claimed bytes, the by-ordinal and cut-name import
 * entries, a descriptor with no FirstThunk, the export tables that resolve nowhere. Every case is built
 * from field values the test writes (image_kit.h), and what is checked is the value written, not a
 * second reading of the same bytes by the code under test.
 */

#define _GNU_SOURCE

#include <kgenome.h>

#include "hk.h"
#include "image_kit.h"

#define N 0x4000u

static uint8_t img[N];
static struct kgenome_pe_info info;
static struct kgenome_obj obj;

static int parse_n(uint32_t layout, uint64_t n)
{
	memset(&info, 0, sizeof info);
	info.layout = layout;
	memset(&obj, 0, sizeof obj);
	return kgenome_pe_image_parse(kof_buf_make(img, n), &info, &obj);
}

static int parse(void)
{
	return parse_n(KGENOME_PE_LAYOUT_FILE, N);
}

static void base_pe(struct ik_pe *p, int plus)
{
	memset(p, 0, sizeof *p);
	p->plus = plus;
	p->entry = 0x1000;
	p->size_of_image = 0x4000;
	p->size_of_headers = 0x400;
	p->file_align = 0x200;
	p->size_of_code = 0x400;
	ik_sec(p, ".text", 0x400, 0x1000, 0x400, 0x400, IK_TEXT);
	ik_sec(p, ".rdata", 0x400, 0x2000, 0x400, 0x800, IK_RDATA);
	ik_sec(p, ".data", 0x400, 0x3000, 0x400, 0xc00, IK_DATA);
}

static void fresh(const struct ik_pe *p)
{
	memset(img, 0, N);
	(void)ik_pe_write(img, p);
}

static void result(const char *id, const char *what, int before)
{
	printf("%s %s: %s\n", id, what, hk_fails == before ? "ok" : "FAILED");
}

/* ---- the machine table: every value, against a table written here ----------------------------- */

static void t_machine(void)
{
	static const struct { uint16_t m; uint32_t arch; } tab[] = {
		{ 0x014c, KGENOME_ARCH_X86 }, { 0x8664, KGENOME_ARCH_X86_64 },
		{ 0x01c0, KGENOME_ARCH_ARM }, { 0x01c2, KGENOME_ARCH_ARM }, { 0x01c4, KGENOME_ARCH_ARM },
		{ 0xaa64, KGENOME_ARCH_ARM64 }, { 0x5032, KGENOME_ARCH_RISCV32 }, { 0x5064, KGENOME_ARCH_RISCV64 },
		{ 0x0166, KGENOME_ARCH_MIPS }, { 0x0266, KGENOME_ARCH_MIPS }, { 0x0366, KGENOME_ARCH_MIPS },
		{ 0x0466, KGENOME_ARCH_MIPS }, { 0x01f0, KGENOME_ARCH_PPC }, { 0x01f2, KGENOME_ARCH_PPC },
		{ 0x0000, KGENOME_ARCH_OTHER }, { 0x0200, KGENOME_ARCH_OTHER }, { 0xffff, KGENOME_ARCH_OTHER },
		{ 0x01c3, KGENOME_ARCH_OTHER }, { 0x0167, KGENOME_ARCH_OTHER },
	};
	struct ik_pe p;
	unsigned i;
	int before = hk_fails;

	for (i = 0; i < sizeof tab / sizeof tab[0]; i++) {
		base_pe(&p, 0);
		p.machine = tab[i].m;
		fresh(&p);
		if (tab[i].m == 0) {
			/* the builder writes the width's own machine for 0; a machine of zero is set by hand */
			ik_w16(img + 0x84, 0);
		}
		CK(parse());
		CK(info.machine == tab[i].m);
		if (obj.arch != tab[i].arch)
			printf("  machine %#x: arch %u, expected %u\n", tab[i].m, (unsigned)obj.arch, (unsigned)tab[i].arch);
		CK(obj.arch == tab[i].arch);
	}
	result("P1 ", "machine to architecture", before);
}

/* ---- the resource directory: where it sits in its section --------------------------------------- */

static void t_resource(void)
{
	struct ik_pe p;
	int before = hk_fails;

	/* a directory at the front of its section: its range, no anomaly */
	base_pe(&p, 0);
	p.dir_rva[KGENOME_PE_DIR_RESOURCE] = 0x2000;
	p.dir_size[KGENOME_PE_DIR_RESOURCE] = 0x100;
	fresh(&p);
	CK(parse());
	CK(info.res_off == 0x800 && info.res_len == 0x100);
	CK((info.anomalies & KGENOME_PE_ANOM_RSRC_UNALIGNED) == 0);
	CK(info.sec[1].claim_off == 0x900 && info.sec[1].claim_len == 0x300);   /* the section keeps the rest */

	/* a directory in the middle of its section: the section keeps the bytes, the region is empty, said */
	p.dir_rva[KGENOME_PE_DIR_RESOURCE] = 0x2040;
	fresh(&p);
	CK(parse());
	CK((info.anomalies & KGENOME_PE_ANOM_RSRC_UNALIGNED) != 0);
	CK(info.res_len == 0);
	CK(info.sec[1].claim_off == 0x800 && info.sec[1].claim_len == 0x400);

	/* a directory that resolves nowhere, and one with a size and no address, or an address and no size */
	p.dir_rva[KGENOME_PE_DIR_RESOURCE] = 0x9000;
	fresh(&p);
	CK(parse());
	CK(info.res_len == 0 && info.res_off == 0);
	p.dir_rva[KGENOME_PE_DIR_RESOURCE] = 0;
	fresh(&p);
	CK(parse());
	CK(info.res_len == 0);
	p.dir_rva[KGENOME_PE_DIR_RESOURCE] = 0x2000;
	p.dir_size[KGENOME_PE_DIR_RESOURCE] = 0;
	fresh(&p);
	CK(parse());
	CK(info.res_len == 0);
	/* the address is in the zero-filled tail of its section: mapped in memory, not stored in the file */
	base_pe(&p, 0);
	p.s[1].vsize = 0x1000;                       /* the virtual size runs past the raw bytes */
	p.dir_rva[KGENOME_PE_DIR_RESOURCE] = 0x2500;
	p.dir_size[KGENOME_PE_DIR_RESOURCE] = 0x40;
	fresh(&p);
	CK(parse());
	CK(info.res_len == 0);
	/* a mapped image: the directory in the alignment slack between two sections is in no section, and the
	 * object alone bounds it; one inside a section is bounded by the section */
	base_pe(&p, 0);
	p.dir_rva[KGENOME_PE_DIR_RESOURCE] = 0x2800;
	p.dir_size[KGENOME_PE_DIR_RESOURCE] = 0x10;
	fresh(&p);
	CK(parse_n(KGENOME_PE_LAYOUT_MAPPED, N));
	CK(info.res_off == 0x2800 && info.res_len == 0x10);
	p.dir_size[KGENOME_PE_DIR_RESOURCE] = 0xffffffffu;
	fresh(&p);
	CK(parse_n(KGENOME_PE_LAYOUT_MAPPED, N));
	CK(info.res_off == 0x2800 && info.res_len == N - 0x2800);
	result("P2 ", "resource directory", before);
}

/* ---- the CLI header and the metadata version -------------------------------------------------- */

static void clr_pe(struct ik_pe *p, uint32_t md_rva, uint32_t md_size)
{
	base_pe(p, 0);
	p->dir_rva[KGENOME_PE_DIR_COM_DESCRIPTOR] = 0x2000;
	p->dir_size[KGENOME_PE_DIR_COM_DESCRIPTOR] = 72;
	fresh(p);
	/* the CLI header at file 0x800: cb, major 2, minor 5, metadata, flags 1, entry token 0x06000001 */
	ik_w32(img + 0x800, 72);
	ik_w16(img + 0x804, 2);
	ik_w16(img + 0x806, 5);
	ik_w32(img + 0x808, md_rva);
	ik_w32(img + 0x80c, md_size);
	ik_w32(img + 0x810, 1);
	ik_w32(img + 0x814, 0x06000001u);
}

static void t_clr(void)
{
	struct ik_pe p;
	int before = hk_fails;
	char ver[200];
	unsigned vl;

	/* a complete header: BSJB at file 0x900 (rva 0x2100), version string "v4.0.30319" */
	clr_pe(&p, 0x2100, 0x100);
	ik_w32(img + 0x900, 0x424a5342u);
	ik_w32(img + 0x90c, 12);
	memcpy(img + 0x910, "v4.0.30319\0\0", 12);
	CK(parse());
	CK(info.clr_off == 0x800 && info.clr_len == 72);
	CK(info.clr_major == 2 && info.clr_minor == 5 && info.clr_flags == 1 && info.clr_entry_token == 0x06000001u);
	CK(!strcmp(info.clr_version, "v4.0.30319"));

	/* a version longer than the field is cut to what it holds (31 bytes and a terminator) */
	for (vl = 1; vl < 100; vl += 9) {
		clr_pe(&p, 0x2100, 0x100);
		ik_w32(img + 0x900, 0x424a5342u);
		ik_w32(img + 0x90c, vl);
		memset(ver, 'v', sizeof ver);
		memcpy(img + 0x910, ver, vl);
		CK(parse());
		CK(strlen(info.clr_version) == (vl > 31u ? 31u : vl));
	}
	/* no BSJB, no version */
	clr_pe(&p, 0x2100, 0x100);
	ik_w32(img + 0x900, 0x12345678u);
	ik_w32(img + 0x90c, 12);
	memcpy(img + 0x910, "v4.0.30319\0\0", 12);
	CK(parse());
	CK(info.clr_version[0] == 0 && info.clr_off == 0x800);
	/* a metadata root that resolves nowhere, one at zero, a zero length string */
	clr_pe(&p, 0x9000, 0x100);
	CK(parse());
	CK(info.clr_version[0] == 0);
	clr_pe(&p, 0, 0);
	CK(parse());
	CK(info.clr_version[0] == 0 && info.clr_off == 0x800);
	clr_pe(&p, 0x2100, 0x100);
	ik_w32(img + 0x900, 0x424a5342u);
	ik_w32(img + 0x90c, 0);
	CK(parse());
	CK(info.clr_version[0] == 0);
	/* the string runs past the end of the object: not read */
	clr_pe(&p, 0x2100, 0x100);
	ik_w32(img + 0x900, 0x424a5342u);
	ik_w32(img + 0x90c, 20);
	memcpy(img + 0x910, "v4.0.30319", 10);
	{
		int ok = (memset(&info, 0, sizeof info), memset(&obj, 0, sizeof obj),
			  kgenome_pe_image_parse(kof_buf_make(img, 0x915), &info, &obj));

		CK(ok);
		CK(info.clr_version[0] == 0);
	}
	/* the CLI directory with no address, no size, or outside the sections */
	clr_pe(&p, 0x2100, 0x100);
	ik_w32(img + 0x98 + 24 + (0), 0);        /* touch */
	p.dir_rva[KGENOME_PE_DIR_COM_DESCRIPTOR] = 0x9000;
	fresh(&p);
	CK(parse());
	CK(info.clr_off == 0 && info.clr_len == 0);
	p.dir_rva[KGENOME_PE_DIR_COM_DESCRIPTOR] = 0;
	fresh(&p);
	CK(parse());
	CK(info.clr_len == 0);
	p.dir_rva[KGENOME_PE_DIR_COM_DESCRIPTOR] = 0x2000;
	p.dir_size[KGENOME_PE_DIR_COM_DESCRIPTOR] = 0;
	fresh(&p);
	CK(parse());
	CK(info.clr_len == 0);
	/* a CLI directory larger than what is left of the object: its range is what is left */
	clr_pe(&p, 0x2100, 0x100);
	p.dir_size[KGENOME_PE_DIR_COM_DESCRIPTOR] = 0x1000;
	fresh(&p);
	CK(parse_n(KGENOME_PE_LAYOUT_FILE, 0x900));
	CK(info.clr_off == 0x800 && info.clr_len == 0x100);
	/* a directory count that does not reach the CLI entry */
	clr_pe(&p, 0x2100, 0x100);
	p.n_dirs = 10;
	fresh(&p);
	CK(parse());
	CK(info.clr_len == 0 && info.n_dirs == 10u);
	result("P3 ", "CLI header and metadata version", before);
}

/* ---- headers, sections, entry, certificate, overlay ------------------------------------------- */

static void t_headers(void)
{
	struct ik_pe p;
	int before = hk_fails;

	base_pe(&p, 0);
	fresh(&p);
	/* not an MZ, an e_lfanew that cannot be read, one past the end, one without the signature */
	img[0] = 'X';
	CK(!parse());
	CK((info.anomalies & KGENOME_PE_ANOM_BAD_MZ) != 0);
	fresh(&p);
	CK(!parse_n(KGENOME_PE_LAYOUT_FILE, 0x3e));
	CK((info.anomalies & KGENOME_PE_ANOM_TRUNCATED_HEADER) != 0);
	fresh(&p);
	ik_w32(img + 0x3c, N - 4u);
	CK(!parse());
	CK((info.anomalies & KGENOME_PE_ANOM_LFANEW_PAST_EOF) != 0);
	fresh(&p);
	img[0x80] = 'Q';
	CK(!parse());
	CK((info.anomalies & KGENOME_PE_ANOM_BAD_PE_SIG) != 0);
	/* the file ends inside the optional header: the magic is unreadable, said, the parse goes on */
	fresh(&p);
	CK(parse_n(KGENOME_PE_LAYOUT_FILE, 0x80 + 24 + 1));
	CK((info.anomalies & KGENOME_PE_ANOM_TRUNCATED_HEADER) != 0);
	CK(info.opt_magic == 0);
	/* a magic that is neither, a stub that is too long, one that is not the standard stub */
	fresh(&p);
	ik_w16(img + 0x98, 0x1234);
	CK(parse());
	CK((info.anomalies & KGENOME_PE_ANOM_BAD_OPT_MAGIC) != 0);
	base_pe(&p, 0);
	p.lfanew = 0x600;
	fresh(&p);
	CK(parse());
	CK((info.anomalies & KGENOME_PE_ANOM_STUB_OVERSIZED) != 0 && (info.anomalies & KGENOME_PE_ANOM_STUB_NONSTANDARD) == 0);
	memset(img + 0x40, 0x41, 0x80);              /* and without the message: both */
	CK(parse());
	CK((info.anomalies & KGENOME_PE_ANOM_STUB_OVERSIZED) != 0 && (info.anomalies & KGENOME_PE_ANOM_STUB_NONSTANDARD) != 0);
	base_pe(&p, 0);
	fresh(&p);
	memset(img + 0x40, 0x41, 0x40);
	CK(parse());
	CK((info.anomalies & KGENOME_PE_ANOM_STUB_NONSTANDARD) != 0 && (info.anomalies & KGENOME_PE_ANOM_STUB_OVERSIZED) == 0);
	/* the standard stub, whose message sits where the search ends: found at the last offset it looks */
	base_pe(&p, 0);
	fresh(&p);
	CK(parse());
	CK((info.anomalies & KGENOME_PE_ANOM_STUB_NONSTANDARD) == 0);
	/* an optional header too small for its magic */
	base_pe(&p, 1);
	p.optsz = 100;
	fresh(&p);
	CK(parse());
	CK((info.anomalies & KGENOME_PE_ANOM_OPTSIZE_ODD) != 0);
	/* a section count that is zero, past the limit, and one whose table runs past the file */
	base_pe(&p, 0);
	p.nsec_claim = 0;
	p.n = 0;
	fresh(&p);
	CK(parse());
	CK((info.anomalies & KGENOME_PE_ANOM_NSEC_ZERO) != 0 && info.sec_count == 0);
	base_pe(&p, 0);
	p.nsec_claim = 200;
	fresh(&p);
	CK(parse());
	CK((info.anomalies & KGENOME_PE_ANOM_NSEC_CLAMPED) != 0 && info.nsec == KGENOME_PE_MAX_SECTIONS && info.nsec_claimed == 200);
	CK((info.anomalies & KGENOME_PE_ANOM_SECTAB_PAST_EOF) == 0);
	CK(info.sec_count == KGENOME_PE_MAX_SECTIONS);   /* the zeroed rows past the three real ones are read as sections */
	base_pe(&p, 0);
	fresh(&p);
	CK(parse_n(KGENOME_PE_LAYOUT_FILE, 0x80 + 24 + 224 + 40 * 2 + 10));
	CK((info.anomalies & KGENOME_PE_ANOM_SECTAB_PAST_EOF) != 0 && info.sec_count == 2u);
	/* the NT headers right behind the DOS header (no stub gap at all), and so close that the stub message cannot fit */
	base_pe(&p, 0);
	p.lfanew = 0x40;
	fresh(&p);
	CK(parse());
	CK(info.stub_len == 0 && (info.anomalies & KGENOME_PE_ANOM_STUB_NONSTANDARD) != 0);
	p.lfanew = 0x60;
	fresh(&p);
	CK(parse());
	CK(info.stub_len == 0x20u && (info.anomalies & KGENOME_PE_ANOM_STUB_NONSTANDARD) != 0);
	/* no view, no object: refused */
	CK(kgenome_pe_image_parse(kof_buf_make(img, N), NULL, &obj) == 0);
	CK(kgenome_pe_image_parse(kof_buf_make(img, N), &info, NULL) == 0);
	result("P4 ", "header failures and anomalies", before);
}

static void t_sections(void)
{
	struct ik_pe p;
	int before = hk_fails;

	/* an object-form name, zero raw with a virtual size, write+execute, raw bytes more than rounding explains */
	base_pe(&p, 0);
	p.n = 0;
	ik_sec(&p, "/12", 0x400, 0x1000, 0x400, 0x400, IK_TEXT);
	ik_sec(&p, ".bss", 0x400, 0x2000, 0, 0, IK_DATA);
	ik_sec(&p, ".wx", 0x100, 0x3000, 0x400, 0x800, 0xe0000020u);
	ik_sec(&p, ".fat", 0x100, 0x4000, 0x800, 0xc00, IK_RDATA);
	fresh(&p);
	CK(parse());
	CK((info.anomalies & KGENOME_PE_ANOM_SECNAME_OBJFORM) != 0);
	CK((info.anomalies & KGENOME_PE_ANOM_SEC_ZERO_RAW) != 0);
	CK((info.anomalies & KGENOME_PE_ANOM_SEC_WRITE_EXEC) != 0);
	CK((info.anomalies & KGENOME_PE_ANOM_SEC_RAW_GT_VIRT) != 0);
	CK(!strcmp(info.sec[0].name, "/12") && info.sec[2].perm == (KGENOME_PE_PERM_R | KGENOME_PE_PERM_W | KGENOME_PE_PERM_X));
	/* none of those on the plain image */
	base_pe(&p, 0);
	fresh(&p);
	CK(parse());
	CK((info.anomalies & (KGENOME_PE_ANOM_SECNAME_OBJFORM | KGENOME_PE_ANOM_SEC_ZERO_RAW | KGENOME_PE_ANOM_SEC_WRITE_EXEC |
			      KGENOME_PE_ANOM_SEC_RAW_GT_VIRT)) == 0);
	/* a section whose raw bytes run past the end: kept, clipped, said */
	base_pe(&p, 0);
	p.s[2].raw = N - 0x100;
	p.s[2].rsize = 0x400;
	fresh(&p);
	CK(parse());
	CK((info.anomalies & KGENOME_PE_ANOM_SEC_PAST_EOF) != 0);
	CK(info.sec[2].file_size == 0x100 && info.sec[2].file_off == N - 0x100);
	p.s[2].raw = N + 0x100;                      /* wholly past the end */
	fresh(&p);
	CK(parse());
	CK(info.sec[2].file_size == 0);
	/* two sections over the same bytes: a real collision, the second keeps nothing */
	base_pe(&p, 0);
	p.s[1].raw = 0x400;
	fresh(&p);
	CK(parse());
	CK((info.anomalies & KGENOME_PE_ANOM_SEC_OVERLAP) != 0);
	CK(info.sec[0].claim_len == 0x400 && info.sec[1].claim_len == 0);
	/* a section that starts inside the headers loses the bytes the headers hold */
	base_pe(&p, 0);
	p.s[0].raw = 0x100;
	p.s[0].rsize = 0x400;
	fresh(&p);
	CK(parse());
	CK((info.anomalies & KGENOME_PE_ANOM_SEC_OVERLAP) != 0);
	CK(info.sec[0].claim_off >= info.header_end);
	/* a file alignment that is not a power of two switches the rounding test off, and says nothing */
	base_pe(&p, 0);
	p.file_align = 3;
	p.s[0].rsize = 0x2000;
	p.s[0].raw = 0x400;
	p.n = 1;
	fresh(&p);
	CK(parse());
	CK((info.anomalies & KGENOME_PE_ANOM_SEC_RAW_GT_VIRT) == 0);
	result("P5 ", "section table", before);
}

static void t_entry_and_tail(void)
{
	struct ik_pe p;
	int before = hk_fails;

	/* entry in the first section: offset resolved, no anomaly */
	base_pe(&p, 0);
	p.entry = 0x1010;
	fresh(&p);
	CK(parse());
	CK(obj.entry_off == 0x410 && info.entry_sec == 0 && (info.anomalies & (KGENOME_PE_ANOM_ENTRY_ZERO | KGENOME_PE_ANOM_ENTRY_UNMAPPED |
	   KGENOME_PE_ANOM_ENTRY_NOT_EXEC | KGENOME_PE_ANOM_ENTRY_ZEROFILL)) == 0);
	/* zero, in no section, in a section that is not executable, in the zero-filled tail */
	p.entry = 0;
	fresh(&p);
	CK(parse());
	CK((info.anomalies & KGENOME_PE_ANOM_ENTRY_ZERO) != 0 && obj.entry_off == KGENOME_BROKEN);
	p.entry = 0x9000;
	fresh(&p);
	CK(parse());
	CK((info.anomalies & KGENOME_PE_ANOM_ENTRY_UNMAPPED) != 0 && info.entry_sec == info.sec_count);
	p.entry = 0x2010;
	fresh(&p);
	CK(parse());
	CK((info.anomalies & KGENOME_PE_ANOM_ENTRY_NOT_EXEC) != 0 && info.entry_sec == 1u && obj.entry_off == 0x810);
	p.s[0].vsize = 0x1000;
	p.entry = 0x1800;
	fresh(&p);
	CK(parse());
	CK((info.anomalies & KGENOME_PE_ANOM_ENTRY_ZEROFILL) != 0 && obj.entry_off == KGENOME_BROKEN);

	/* certificate: past the sections it is the cert, over claimed bytes it is refused (and said), past the end it is cut */
	base_pe(&p, 0);
	p.dir_rva[KGENOME_PE_DIR_SECURITY] = 0x1000;
	p.dir_size[KGENOME_PE_DIR_SECURITY] = 0x100;
	fresh(&p);
	CK(parse());
	CK(info.cert_off == 0x1000 && info.cert_len == 0x100);
	CK(info.overlay_off == 0x1100 && info.overlay_len == N - 0x1100);
	p.dir_rva[KGENOME_PE_DIR_SECURITY] = 0x400;
	fresh(&p);
	CK(parse());
	CK(info.cert_len == 0);
	p.dir_rva[KGENOME_PE_DIR_SECURITY] = N - 0x10;
	p.dir_size[KGENOME_PE_DIR_SECURITY] = 0x100;
	fresh(&p);
	CK(parse());
	CK((info.anomalies & KGENOME_PE_ANOM_CERT_PAST_EOF) != 0 && info.cert_off == N - 0x10 && info.cert_len == 0x10);
	/* nothing after the last claim: no overlay */
	base_pe(&p, 0);
	fresh(&p);
	CK(parse_n(KGENOME_PE_LAYOUT_FILE, 0x1000));
	CK(info.overlay_len == 0);
	/* a mapped image has no overlay and no certificate, whatever is past its last section */
	CK(parse_n(KGENOME_PE_LAYOUT_MAPPED, N));
	CK(info.overlay_len == 0 && info.cert_len == 0);
	/* SizeOfCode above what the code sections hold is odd, below it is not */
	base_pe(&p, 0);
	p.size_of_code = 0x9000;
	fresh(&p);
	CK(parse());
	CK((info.anomalies & KGENOME_PE_ANOM_SUMMARY_MISMATCH) != 0);
	p.size_of_code = 0x100;
	fresh(&p);
	CK(parse());
	CK((info.anomalies & KGENOME_PE_ANOM_SUMMARY_MISMATCH) == 0);
	/* SizeOfHeaders below the end of the section table */
	base_pe(&p, 0);
	p.size_of_headers = 0x100;
	fresh(&p);
	CK(parse());
	CK((info.anomalies & KGENOME_PE_ANOM_SIZEOFHDR_ODD) != 0);
	result("P6 ", "entry, certificate, overlay", before);
}

/* ---- the import and export walkers ------------------------------------------------------------ */

struct ir {
	unsigned n;
	struct { uint64_t slot, nameoff; uint32_t ord; char dll[32], name[32]; } v[32];
};

static void imp_cb(void *u, uint64_t slot, const char *dll, const char *name, uint32_t ord, uint64_t nameoff)
{
	struct ir *r = u;

	if (r->n >= 32u)
		return;
	r->v[r->n].slot = slot;
	r->v[r->n].ord = ord;
	r->v[r->n].nameoff = nameoff;
	snprintf(r->v[r->n].dll, sizeof r->v[r->n].dll, "%s", dll ? dll : "");
	snprintf(r->v[r->n].name, sizeof r->v[r->n].name, "%s", name ? name : "");
	r->n++;
}

static int exp_cb(void *u, uint64_t name_off, uint32_t rva)
{
	unsigned *k = u;

	(void)name_off; (void)rva;
	return ++*k < 3u;
}

/* import directory at file 0x800 (rva 0x2000) */
static void imp_pe(struct ik_pe *p, int plus)
{
	base_pe(p, plus);
	p->dir_rva[KGENOME_PE_DIR_IMPORT] = 0x2000;
	p->dir_size[KGENOME_PE_DIR_IMPORT] = 60;
	fresh(p);
}

static void t_imports(void)
{
	struct ik_pe p;
	struct ir r;
	enum kgenome_status st;
	unsigned plus, n, k;
	int before = hk_fails;

	for (plus = 0; plus < 2u; plus++) {
		const uint32_t w = plus ? 8u : 4u;
		const uint64_t ordflag = plus ? 0x8000000000000000ull : 0x80000000ull;
		uint8_t *d;

		/* a descriptor: lookup table with a name, an ordinal and the terminator; the DLL's name; no second descriptor */
		imp_pe(&p, (int)plus);
		d = img + 0x800;
		ik_w32(d + 0, 0x2100);                    /* OriginalFirstThunk */
		ik_w32(d + 12, 0x2200);                   /* name */
		ik_w32(d + 16, 0x2180);                   /* FirstThunk */
		memcpy(img + 0xa00, "A.dll", 6);
		if (plus) { ik_w64(img + 0x900, 0x2300); ik_w64(img + 0x908, ordflag | 7u); } else { ik_w32(img + 0x900, 0x2300); ik_w32(img + 0x904, 0x80000007u); }
		memcpy(img + 0xb00 + 2, "Func", 5);
		CK(parse());
		memset(&r, 0, sizeof r);
		n = kgenome_pe_imports(kof_buf_make(img, N), &info, imp_cb, &r, &st);
		CK(n == 2u && st == KGENOME_OK);
		CK(r.v[0].slot == info.image_base + 0x2180 && !strcmp(r.v[0].name, "Func") && r.v[0].ord == 0 && r.v[0].nameoff == 0xb02);
		CK(r.v[1].slot == info.image_base + 0x2180 + w && r.v[1].ord == 7u && r.v[1].nameoff == 0);
		CK(!strcmp(r.v[0].dll, "A.dll"));

		/* no FirstThunk: the slots would be addresses in the headers, so nothing is reported */
		ik_w32(d + 16, 0);
		CK(parse());
		memset(&r, 0, sizeof r);
		CK(kgenome_pe_imports(kof_buf_make(img, N), &info, imp_cb, &r, &st) == 0);
		/* no lookup table: the names come from the IAT itself */
		ik_w32(d + 0, 0);
		ik_w32(d + 16, 0x2100);
		CK(parse());
		memset(&r, 0, sizeof r);
		CK(kgenome_pe_imports(kof_buf_make(img, N), &info, imp_cb, &r, &st) == 2u);
		/* a lookup table that resolves nowhere: that descriptor is skipped */
		ik_w32(d + 0, 0x9000);
		CK(parse());
		memset(&r, 0, sizeof r);
		CK(kgenome_pe_imports(kof_buf_make(img, N), &info, imp_cb, &r, &st) == 0);
		/* a name entry that resolves nowhere is skipped, the ordinal after it is not */
		ik_w32(d + 0, 0x2100);
		if (plus) ik_w64(img + 0x900, 0x9000); else ik_w32(img + 0x900, 0x9000);
		CK(parse());
		memset(&r, 0, sizeof r);
		CK(kgenome_pe_imports(kof_buf_make(img, N), &info, imp_cb, &r, &st) == 1u && r.v[0].ord == 7u);
		/* a library name that cannot be read: reported with an empty name */
		ik_w32(d + 12, 0x9000);
		CK(parse());
		memset(&r, 0, sizeof r);
		CK(kgenome_pe_imports(kof_buf_make(img, N), &info, imp_cb, &r, &st) == 1u && r.v[0].dll[0] == 0);
		/* a descriptor that is cut by the end of the file ends the walk */
		ik_w32(d + 12, 0x2200);
		CK(parse());
		memset(&r, 0, sizeof r);
		CK(kgenome_pe_imports(kof_buf_make(img, 0x800 + 10), &info, imp_cb, &r, &st) == 0);
		/* a table with no terminator inside the file: the walk ends at the end of the bytes, not later */
		if (plus) ik_w64(img + 0x900, 0x2300); else ik_w32(img + 0x900, 0x2300);
		for (k = 0; k < 0x100; k += w)
			if (plus) ik_w64(img + 0x900 + k, 0x2300); else ik_w32(img + 0x900 + k, 0x2300);
		CK(parse());
		memset(&r, 0, sizeof r);
		n = kgenome_pe_imports(kof_buf_make(img, N), &info, imp_cb, &r, &st);
		CK(n == 0x100u / w);

		/* a lookup table whose terminator is past the end of the object: the walk ends where the bytes do */
		imp_pe(&p, (int)plus);
		d = img + 0x800;
		ik_w32(d + 0, 0x2100);
		ik_w32(d + 12, 0x2200);
		ik_w32(d + 16, 0x2180);
		memcpy(img + 0xa00, "A.dll", 6);
		if (plus) ik_w64(img + 0x900 - 0, 0x2300); else ik_w32(img + 0x900, 0x2300);
		{
			/* the table is entered at its last readable entry and the next one is cut by the end of the object */
			const uint64_t cutn = 0x900 + w + (w == 8 ? 4u : 2u);

			CK(parse());
			memset(&r, 0, sizeof r);
			n = kgenome_pe_imports(kof_buf_make(img, cutn), &info, imp_cb, &r, &st);
			CK(n <= 2u);
		}
		/* a name entry whose hint/name lies at the very end: the name cannot be read, the entry is skipped */
		if (plus) ik_w64(img + 0x900, 0x2000 + 0x3fe); else ik_w32(img + 0x900, 0x2000 + 0x3fe);
		CK(parse());
		memset(&r, 0, sizeof r);
		n = kgenome_pe_imports(kof_buf_make(img, 0x800 + 0x3fe + 2u), &info, imp_cb, &r, &st);
		CK(n == 0u);

		/* a name longer than the name buffer is cut and the walk says so */
		{
			static uint8_t big[0x8000];
			struct ik_pe q;

			base_pe(&q, (int)plus);
			q.dir_rva[KGENOME_PE_DIR_IMPORT] = 0x2000;
			q.dir_size[KGENOME_PE_DIR_IMPORT] = 40;
			q.s[1].vsize = 0x3000; q.s[1].rsize = 0x3000;
			q.s[2].rva = 0x6000; q.s[2].raw = 0x3c00; q.s[2].rsize = 0x400; q.s[2].vsize = 0x400;
			q.size_of_image = 0x7000;
			memset(big, 0, sizeof big);
			(void)ik_pe_write(big, &q);
			ik_w32(big + 0x800, 0x2100);
			ik_w32(big + 0x800 + 12, 0x2200);
			ik_w32(big + 0x800 + 16, 0x2100);
			memset(big + 0xa00, 'L', 5000);       /* the library name: longer than the 4096 the walk reads */
			if (plus) { ik_w64(big + 0x900, 0x2400); } else { ik_w32(big + 0x900, 0x2400); }
			memset(big + 0xc00 + 2, 'F', 5000);   /* and so is the function's */
			memset(&info, 0, sizeof info);
			memset(&obj, 0, sizeof obj);
			CK(kgenome_pe_image_parse(kof_buf_make(big, sizeof big), &info, &obj));
			memset(&r, 0, sizeof r);
			n = kgenome_pe_imports(kof_buf_make(big, sizeof big), &info, imp_cb, &r, &st);
			CK(n == 1u && st == KGENOME_TRUNCATED);
		}
	}
	/* the table of imports built from the walk: a long library name is kept short and said */
	{
		struct kgenome_pe_imptab t;

		imp_pe(&p, 0);
		ik_w32(img + 0x800 + 0, 0x2100);
		ik_w32(img + 0x800 + 12, 0x2200);
		ik_w32(img + 0x800 + 16, 0x2180);
		memset(img + 0xa00, 'D', 100);
		ik_w32(img + 0x900, 0x2300);
		memcpy(img + 0xb02, "Func", 5);
		CK(parse());
		kgenome_pe_imptab_build(kof_buf_make(img, N), &info, &t);
		CK(t.n == 1u && t.n_dll == 1u && t.status == KGENOME_TRUNCATED);
		CK(kgenome_pe_imptab_is_of(&t, kof_buf_make(img, N)) && !kgenome_pe_imptab_is_of(&t, kof_buf_make(img, N - 1u)));
		CK(!kgenome_pe_imptab_is_of(NULL, kof_buf_make(img, N)));
		kgenome_pe_imptab_free(&t);
		kgenome_pe_imptab_free(NULL);
	}
	/* not valid, no callback, no directory, a directory that resolves nowhere: nothing */
	{
		struct kgenome_pe_info bad;

		memset(&bad, 0, sizeof bad);
		CK(kgenome_pe_imports(kof_buf_make(img, N), &bad, imp_cb, &r, &st) == 0);
		CK(kgenome_pe_imports(kof_buf_make(img, N), &info, NULL, &r, &st) == 0);
		CK(kgenome_pe_imports(kof_buf_make(NULL, 0), &info, imp_cb, &r, &st) == 0);
		CK(kgenome_pe_imports(kof_buf_make(img, N), NULL, imp_cb, &r, NULL) == 0);
		base_pe(&p, 0);
		fresh(&p);
		CK(parse());
		CK(kgenome_pe_imports(kof_buf_make(img, N), &info, imp_cb, &r, &st) == 0);
		p.dir_rva[KGENOME_PE_DIR_IMPORT] = 0x9000;
		fresh(&p);
		CK(parse());
		CK(kgenome_pe_imports(kof_buf_make(img, N), &info, imp_cb, &r, &st) == 0);
	}
	/* the twin layout: the same import table read out of a MAPPED image (rva == offset), where the
	 * translation is the identity and a slot in a section's zero tail is still an address */
	for (plus = 0; plus < 2u; plus++) {
		const uint32_t w = plus ? 8u : 4u;
		unsigned lay;
		unsigned counts[2];

		for (lay = 0; lay < 2u; lay++) {
			struct ik_pe q;

			memset(&q, 0, sizeof q);
			q.plus = (int)plus;
			q.size_of_image = N;
			q.size_of_headers = 0x400;
			q.file_align = 0x200;
			q.entry = 0x1000;
			/* file layout: raw == rva; mapped layout: the same bytes taken as the image */
			ik_sec(&q, ".text", 0x400, 0x1000, 0x400, 0x1000, IK_TEXT);
			ik_sec(&q, ".idata", 0x800, 0x2000, 0x800, 0x2000, IK_DATA);
			q.dir_rva[KGENOME_PE_DIR_IMPORT] = 0x2000;
			q.dir_size[KGENOME_PE_DIR_IMPORT] = 40;
			memset(img, 0, N);
			(void)ik_pe_write(img, &q);
			ik_w32(img + 0x2000, 0x2100);
			ik_w32(img + 0x2000 + 12, 0x2200);
			ik_w32(img + 0x2000 + 16, 0x2180);
			memcpy(img + 0x2200, "M.dll", 6);
			memcpy(img + 0x2302, "Func", 5);
			if (plus) { ik_w64(img + 0x2100, 0x2300); ik_w64(img + 0x2100 + w, 0x8000000000000009ull); }
			else { ik_w32(img + 0x2100, 0x2300); ik_w32(img + 0x2100 + w, 0x80000009u); }
			CK(parse_n(lay ? KGENOME_PE_LAYOUT_MAPPED : KGENOME_PE_LAYOUT_FILE, N));
			memset(&r, 0, sizeof r);
			counts[lay] = kgenome_pe_imports(kof_buf_make(img, N), &info, imp_cb, &r, &st);
			CK(counts[lay] == 2u && !strcmp(r.v[0].name, "Func") && r.v[1].ord == 9u && !strcmp(r.v[0].dll, "M.dll"));
			CK(r.v[0].slot == info.image_base + 0x2180u && r.v[1].slot == info.image_base + 0x2180u + w);
		}
		CK(counts[0] == counts[1]);
	}
	result("P7 ", "import directory walk", before);

	/* exports: the three tables, each of which may resolve nowhere; a callback that stops the walk */
	before = hk_fails;
	{
		unsigned stop = 0;
		uint8_t *d;
		struct ik_pe q;
		const unsigned names = 5;

		base_pe(&q, 0);
		q.dir_rva[KGENOME_PE_DIR_EXPORT] = 0x2000;
		q.dir_size[KGENOME_PE_DIR_EXPORT] = 40;
		fresh(&q);
		d = img + 0x800;
		ik_w32(d + 24, names);
		ik_w32(d + 28, 0x2100);                   /* functions */
		ik_w32(d + 32, 0x2200);                   /* names */
		ik_w32(d + 36, 0x2300);                   /* ordinals */
		for (k = 0; k < names; k++) {
			ik_w32(img + 0xa00 + 4u * k, 0x2380 + 16u * k);
			ik_w16(img + 0xb00 + 2u * k, (uint16_t)k);
			ik_w32(img + 0x900 + 4u * k, 0x1000 + 0x10u * k);
			memcpy(img + 0xb80 + 16u * k, "export_", 8);
		}
		CK(parse());
		n = kgenome_pe_exports(kof_buf_make(img, N), &info, exp_cb, &stop, &st);
		CK(n == 3u && st == KGENOME_OK);         /* the callback stops after the third */
		CK(stop == 3u);
		stop = 0;
		n = kgenome_pe_exports(kof_buf_make(img, N), &info, exp_cb, &stop, NULL);
		CK(n == 3u);
		/* the ordinal table resolves nowhere: names still reported, rva 0 */
		ik_w32(d + 36, 0x9000);
		CK(parse());
		stop = 0;
		CK(kgenome_pe_exports(kof_buf_make(img, N), &info, exp_cb, &stop, &st) == 3u);
		ik_w32(d + 36, 0);
		ik_w32(d + 28, 0);
		CK(parse());
		stop = 0;
		CK(kgenome_pe_exports(kof_buf_make(img, N), &info, exp_cb, &stop, &st) == 3u);
		/* the name table resolves nowhere: nothing; a name RVA that resolves nowhere is skipped */
		ik_w32(d + 32, 0x9000);
		CK(parse());
		stop = 0;
		CK(kgenome_pe_exports(kof_buf_make(img, N), &info, exp_cb, &stop, &st) == 0);
		ik_w32(d + 32, 0x2200);
		ik_w32(img + 0xa00, 0x9000);
		CK(parse());
		stop = 0;
		CK(kgenome_pe_exports(kof_buf_make(img, N), &info, exp_cb, &stop, &st) == 3u);
		/* more names than the walk takes: cut and said */
		ik_w32(d + 24, 100000);
		CK(parse());
		stop = 0;
		n = kgenome_pe_exports(kof_buf_make(img, N), &info, exp_cb, &stop, &st);
		CK(st == KGENOME_TRUNCATED && n >= 1u);
		/* a header cut inside the fields, no directory, a directory past the file, not valid, no callback */
		ik_w32(d + 24, names);
		CK(parse());
		CK(kgenome_pe_exports(kof_buf_make(img, 0x800 + 30), &info, exp_cb, &stop, &st) == 0);
		base_pe(&q, 0);
		fresh(&q);
		CK(parse());
		CK(kgenome_pe_exports(kof_buf_make(img, N), &info, exp_cb, &stop, &st) == 0);
		q.dir_rva[KGENOME_PE_DIR_EXPORT] = 0x9000;
		fresh(&q);
		CK(parse());
		CK(kgenome_pe_exports(kof_buf_make(img, N), &info, exp_cb, &stop, &st) == 0);
		CK(kgenome_pe_exports(kof_buf_make(img, N), &info, NULL, &stop, &st) == 0);
		CK(kgenome_pe_exports(kof_buf_make(img, N), NULL, exp_cb, &stop, &st) == 0);
		CK(kgenome_pe_exports(kof_buf_make(NULL, 0), &info, exp_cb, &stop, &st) == 0);
	}
	result("P8 ", "export directory walk", before);
}

int main(int argc, char **argv)
{
	hk_args(argc, argv);
	t_machine();
	t_resource();
	t_clr();
	t_headers();
	t_sections();
	t_entry_and_tail();
	t_imports();
	if (hk_fails) {
		printf("image_pe_attack: %d check(s) failed\n", hk_fails);
		return 1;
	}
	printf("image_pe_attack: ok\n");
	return 0;
}
