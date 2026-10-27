#define _GNU_SOURCE

/*
 * kofexaminer_cont.c - the printers of every container and document format
 * (gzip, OLE, zip, tar, 7z, rar, cab, lnk, reg, lha, arj, chm, bz2, xz, rtf, pdf)
 * and print_view, which picks the printer from what the parse said the object is.
 * Split from kofexaminer.c by format family, no logic changed.
 */

#include "kofexaminer_private.h"


/*
 * What a gzip wrapper says about the stream it holds, before anything decodes it.
 *
 * The declared ratio is printed beside the sizes rather than left to be worked
 * out: it is the number worth looking at first on a container, and a file that
 * admits to expanding a thousandfold is one to open deliberately.
 */
static void print_gzip(const void *v, const struct kof_obj_ctx *ctx, kof_buf buf)
{
	const struct kof_gzip_info *g = v;

	(void)ctx;
	(void)buf;

	printf("  method    %u%s\n", g->method,
	       g->method == KOF_GZIP_DEFLATE ? " (deflate)" : " (not deflate)");
	printf("  flags     0x%02x%s%s%s%s%s\n", g->flags,
	       (g->flags & KOF_GZIP_FTEXT)    ? " TEXT"    : "",
	       (g->flags & KOF_GZIP_FHCRC)    ? " HCRC"    : "",
	       (g->flags & KOF_GZIP_FEXTRA)   ? " EXTRA"   : "",
	       (g->flags & KOF_GZIP_FNAME)    ? " NAME"    : "",
	       (g->flags & KOF_GZIP_FCOMMENT) ? " COMMENT" : "");
	printf("  mtime     %u   os=%u xfl=%u\n", g->mtime, g->os, g->xfl);
	printf("  stream    off=%llu len=%llu\n",
	       (unsigned long long)g->data_off, (unsigned long long)g->data_len);
	if (g->name_len)
		printf("  name      off=%llu len=%llu\n",
		       (unsigned long long)g->name_off,
		       (unsigned long long)g->name_len);
	if (g->comment_len)
		printf("  comment   off=%llu len=%llu\n",
		       (unsigned long long)g->comment_off,
		       (unsigned long long)g->comment_len);
	if (g->trailer_off) {
		printf("  trailer   off=%llu crc=0x%08x isize=%u",
		       (unsigned long long)g->trailer_off, g->crc32, g->isize);
		if (g->data_len && g->isize / g->data_len >= 100u)
			kex_note_warn("declared expansion is large");
		printf("\n");
	}
}

/*
 * What a compound file holds, before a byte of any stream is joined up.
 *
 * The four content sizes are the point of the display. They are what the directory
 * DECLARED, which is available for free, and the question they answer is the one
 * worth asking first about a document: how much of it is macros. A file whose
 * macros outweigh its text is not a document that happens to have a macro.
 *
 * Runs are printed as a count per class rather than listed, because the number is
 * the interesting part - it is how fragmented the stream is, and so how much a
 * gather would have to join.
 */
static void print_docole(const void *v, const struct kof_obj_ctx *ctx, kof_buf buf)
{
	static const char *const cls_name[KOF_DOCOLE_CLS_COUNT] = {
		"headers", "directory", "content_data", "content_macros",
		"content_metadata", "resources"
	};
	const struct kof_docole_info *o = v;
	uint32_t runs[KOF_DOCOLE_CLS_COUNT] = { 0 };
	uint32_t i;

	(void)ctx;
	(void)buf;

	printf("  version   %u.%u   sector=%u mini=%u cutoff=%u\n",
	       o->major, o->minor, o->sector_size, o->mini_sector_size,
	       o->mini_cutoff);
	printf("  directory %u entries: %u streams, %u storages%s%s\n",
	       o->dir_count, o->stream_count, o->storage_count,
	       o->has_macros ? ", macros present" : "",
	       o->encrypted ? ", CONTENT IS ENCRYPTED" : "");
	printf("  declared  data=%llu macros=%llu metadata=%llu resources=%llu%s\n",
	       (unsigned long long)o->data_bytes,
	       (unsigned long long)o->macro_bytes,
	       (unsigned long long)o->meta_bytes,
	       (unsigned long long)o->resource_bytes, "");
	if (o->macro_bytes > KOF_DOCOLE_MACRO_SUSPECT)
		kex_note_warn("macros are larger than any honest document");

	for (i = 0; i < o->n_runs; i++) {
		if (o->run[i].cls >= KOF_DOCOLE_CLS_COUNT)
			continue;
		runs[o->run[i].cls]++;
	}
	for (i = 0; i < KOF_DOCOLE_CLS_COUNT; i++)
		if (runs[i])
			printf("  %-17s %llu bytes in %u run%s\n", cls_name[i],
			       (unsigned long long)o->region_bytes[i], runs[i],
			       runs[i] == 1 ? "" : "s");
}





/*
 * An entry name, as it is safe to put on a line.
 *
 * The FULL name, path and all, unlike the label the scanner puts in a report - a
 * report answers "which entry", and this answers "what does this archive hold",
 * and the second one wants word/vbaProject.bin rather than vbaProject.bin.
 *
 * The filtering is the same either way and is here rather than at each printer
 * because it was written twice, once for zip and once for tar, identically. Two
 * copies of the rule that keeps a terminal escape out of the output is one copy too
 * many: the name comes from the archive, and an ESC in it rewrites the line.
 */
static void print_entry_name(kof_buf buf, uint64_t off, uint32_t len, uint32_t cap)
{
	uint32_t k;

	for (k = 0; k < len && k < cap && kof_in_range(buf, off + k, 1); k++) {
		uint8_t c = buf.p[off + k];

		putchar(c >= 0x20 && c < 0x7f ? (int)c : '.');
	}
}

/*
 * What an archive states about itself, before a byte of any entry is decoded.
 *
 * The entry table is the display, not a summary of it: a zip's evidence IS its
 * entries - what they are called, how they are packed, whether they can be read at
 * all - and a total hides exactly the one row that matters. Capped, because an APK
 * has hundreds and nobody reads those; the ones marked suspicious are printed
 * whatever their position, so the cap can never hide the interesting one.
 *
 * Each row names the REGION its data landed in, and that column is there to stop
 * this table and --dump from looking like two unrelated descriptions of one file.
 * They describe different things on purpose - a table of entries is what the
 * archive says it holds, and a dump of regions is what a signature would actually
 * be searched over - and without the column there is nothing connecting them. With
 * it, every byte of every row can be found in exactly one dumped file.
 *
 * What this tool does NOT show is the entries OPENED: decompressing them costs
 * budget and belongs to an unpacker, which runs in the scanner and not here. The
 * scanner is where the tree is - it names children as <file>//6//0 - and a .docm
 * reaches its macros three layers down that way, through zip, then the compound
 * file inside it, then the macro streams.
 */
#define ZIP_SHOW 12u

static void print_zip(const void *v, const struct kof_obj_ctx *ctx, kof_buf buf)
{
	const struct kof_zip_info *z = v;
	uint32_t i, shown = 0;

	(void)ctx;

	printf("  kind      %s   %u entries", kof_zip_kind_name(z->kind),
	       z->n_entries);
	if (z->declared_entries != z->n_entries)
		printf(" (%u declared)", z->declared_entries);
	if (z->n_encrypted)
		printf(", %u ENCRYPTED", z->n_encrypted);
	printf("\n");
	printf("  central   off=%llu size=%llu   eocd=%llu\n",
	       (unsigned long long)z->cd_off, (unsigned long long)z->cd_size,
	       (unsigned long long)z->eocd_off);
	printf("  declared  packed=%llu unpacked=%llu",
	       (unsigned long long)z->total_csize,
	       (unsigned long long)z->total_usize);
	if (z->total_csize)
		printf("   ratio %.1fx",
		       (double)z->total_usize / (double)z->total_csize);
	printf("\n");
	if (z->comment_len)
		printf("  comment   off=%llu len=%llu\n",
		       (unsigned long long)z->comment_off,
		       (unsigned long long)z->comment_len);

	for (i = 0; i < z->n_entries; i++) {
		const struct kof_zip_entry *e = &z->entry[i];

		if (shown >= ZIP_SHOW && !e->suspicious)
			continue;
		shown++;
		printf("    [%3u] m=%-3u %9llu -> %-9llu @%-9llu %-6s ", i, e->method,
		       (unsigned long long)e->csize, (unsigned long long)e->usize,
		       (unsigned long long)e->data_off,
		       !e->data_off ? "-" :
		       (e->method == KOF_ZIP_M_STORE &&
			!(e->suspicious & KOF_ZIP_ENT_ENCRYPTED))
		       ? "STORED" : "PACKED");
		print_entry_name(buf, e->name_off, e->name_len, 60u);
		if (e->suspicious & KOF_ZIP_ENT_TRAVERSAL)
			kex_note_bad("ESCAPES THE EXTRACT ROOT");
		if (e->suspicious & KOF_ZIP_ENT_ENCRYPTED)
			kex_note_warn("encrypted");
		if (e->suspicious & KOF_ZIP_ENT_NO_LOCAL)
			kex_note_bad("no local header there");
		if (e->suspicious & KOF_ZIP_ENT_RATIO)
			kex_note_bad("declared expansion is absurd");
		printf("\n");
	}
	if (z->n_entries > shown)
		printf("    ... %u more\n", z->n_entries - shown);
}


/*
 * The subtype's name, which only means anything alongside the format.
 *
 * Here rather than in a format header because it is a spelling for a person, and
 * both enums are already the values the header field holds - elf.h and pe.h say
 * what they mean, and this says how to print them.
 */

/*
 * What a tar holds. The entry table is the display for the reason a zip's is: the
 * evidence in an archive IS its entries, and a total hides the one row that matters.
 */
static void print_tar(const void *v, const struct kof_obj_ctx *ctx, kof_buf buf)
{
	const struct kof_tar_info *t = v;
	uint32_t i, shown = 0;

	(void)ctx;

	printf("  entries   %u: %u file(s), %u dir(s), %u link(s)\n",
	       t->n_entries, t->n_files, t->n_dirs, t->n_links);
	printf("  declared  %llu bytes of content",
	       (unsigned long long)t->total_size);
	if (!t->end_off)
		kex_note_bad("no end blocks: cut short");
	printf("\n");

	for (i = 0; i < t->n_entries; i++) {
		const struct kof_tar_entry *e = &t->entry[i];

		if (shown >= 12u && !e->suspicious)
			continue;
		shown++;
		printf("    [%3u] %c %9llu @%-9llu ", i,
		       e->typeflag ? (char)e->typeflag : '0',
		       (unsigned long long)e->size,
		       (unsigned long long)e->data_off);
		print_entry_name(buf, e->name_off, e->name_len, 60u);
		if (e->suspicious & KOF_TAR_ENT_TRAVERSAL)
			kex_note_bad("ESCAPES THE EXTRACT ROOT");
		if (e->suspicious & KOF_TAR_ENT_PAST_EOF)
			kex_note_bad("content is not in this file");
		if (e->suspicious & KOF_TAR_ENT_SLACK)
			kex_note_bad("padding is not zeroes");
		if (e->suspicious & KOF_TAR_ENT_BAD_SUM)
			kex_note_bad("checksum disagrees");
		printf("\n");
	}
	if (t->n_entries > shown)
		printf("    ... %u more\n", t->n_entries - shown);
}


/*
 * What a 7z states about itself without anything being decoded.
 *
 * The header kind is the line worth reading: it is the difference between an
 * archive this build cannot open yet and one that no build ever will.
 */
static void print_7z(const void *v, const struct kof_obj_ctx *ctx, kof_buf buf)
{
	const struct kof_7z_info *z = v;

	(void)ctx;
	(void)buf;

	printf("  version   %u.%u\n", z->major, z->minor);
	printf("  header    %s at %llu, %llu bytes",
	       kof_7z_header_kind_name(z->header_kind),
	       (unsigned long long)z->next_hdr_off,
	       (unsigned long long)z->next_hdr_size);
	if (z->hdr_coder)
		printf("   coder=0x%06x", z->hdr_coder);
	printf("\n");
	if (z->hdr_pack_size)
		printf("  coded at  %llu, %llu bytes -> %llu   lc=%u lp=%u pb=%u\n",
		       (unsigned long long)z->hdr_pack_off,
		       (unsigned long long)z->hdr_pack_size,
		       (unsigned long long)z->hdr_unpack_size,
		       z->hdr_lc, z->hdr_lp, z->hdr_pb);
	if (z->header_kind == KOF_7Z_HDR_ENCRYPTED)
		printf("  note      the file list itself is ciphertext: nothing in "
		       "this archive is readable\n");
	else if (z->header_kind == KOF_7Z_HDR_CODED)
		printf("  note      the file list is compressed: entries are not "
		       "listed until it is decoded\n");
}


/*
 * What a RAR states about itself, which for RAR3 is nearly everything except the
 * content: every name, size and flag is in the clear.
 */
static void print_rar(const void *v, const struct kof_obj_ctx *ctx, kof_buf buf)
{
	const struct kof_rar_info *r = v;
	uint32_t i, shown = 0;

	(void)ctx;

	printf("  version   RAR%u   %u entries", r->rar_version, r->n_entries);
	if (r->n_encrypted)
		printf(", %u ENCRYPTED", r->n_encrypted);
	if (r->n_stored)
		printf(", %u stored", r->n_stored);
	printf("\n");
	printf("  declared  packed=%llu unpacked=%llu",
	       (unsigned long long)r->total_csize,
	       (unsigned long long)r->total_usize);
	if (r->total_csize)
		printf("   ratio %.1fx",
		       (double)r->total_usize / (double)r->total_csize);
	printf("\n");
	if (r->anomalies & KOF_RAR_ANOM_UNSUPPORTED)
		printf("  note      RAR5: structure walked; compressed entries need a\n"
		       "            decoder this build does not have\n");
	if (r->anomalies & KOF_RAR_ANOM_SOLID)
		printf("  note      solid: entries share one compression window, so "
		       "none can be decoded alone\n");

	for (i = 0; i < r->n_entries; i++) {
		const struct kof_rar_entry *e = &r->entry[i];

		if (shown >= ZIP_SHOW && !e->suspicious)
			continue;
		shown++;
		printf("    [%3u] m=%02x %9llu -> %-9llu @%-9llu %-6s ", i,
		       e->method, (unsigned long long)e->csize,
		       (unsigned long long)e->usize,
		       (unsigned long long)e->data_off,
		       !e->data_off ? "-" :
		       (e->method == KOF_RAR_M_STORE &&
			!(e->suspicious & KOF_RAR_ENT_ENCRYPTED))
		       ? "STORED" : "PACKED");
		print_entry_name(buf, e->name_off, e->name_len, 60u);
		if (e->suspicious & KOF_RAR_ENT_TRAVERSAL)
			kex_note_bad("ESCAPES THE EXTRACT ROOT");
		if (e->suspicious & KOF_RAR_ENT_ENCRYPTED)
			kex_note_warn("encrypted");
		if (e->suspicious & KOF_RAR_ENT_PAST_EOF)
			kex_note_bad("data runs past the end");
		if (e->suspicious & KOF_RAR_ENT_RATIO)
			kex_note_bad("declared expansion is absurd");
		if (e->suspicious & KOF_RAR_ENT_SPLIT)
			kex_note_warn("split across volumes");
		printf("\n");
	}
	if (r->n_entries > shown)
		printf("    ... %u more\n", r->n_entries - shown);
}


/* What an xz says about itself, which is where its blocks are and what codes
 * them - both of which come from the index rather than from the blocks. */
/*
 * Four bytes is the whole wrapper, so this is four bytes' worth of report - and
 * it exists anyway, because "bzip2, level 9, 3849 bytes coded" is the
 * difference between a reader seeing what was recognised and seeing a format
 * name with nothing under it. What is inside is the unpacker's line below.
 */
/*
 * The three archives that arrived together, printed the same way.
 *
 * WHAT EACH ONE'S SECOND LINE IS FOR: how much of the archive this build can
 * actually point at, and how much of it is behind a coding. The two used to be
 * the same number and are not any more - MSZIP and LZX folders, "-lh5-" and
 * ARJ's method 1 are all decoded now - so "openable" and "coded" overlap, and
 * saying so is the point: a report that listed only the stored files would read
 * as an archive with three files in it when it has thirty.
 *
 * A CODED ENTRY IS PRINTED AS ONE. Its `off` is not where its bytes are - for a
 * cabinet it is not a range of the file at all - so printing a number there
 * would be printing a zero and calling it an offset.
 */

/* What the entry says it is coded with, as a word. Empty for a stored one,
 * which is most of them - see kof_unp_method_name. */
static const char *ent_coding(const struct kof_entry *e)
{
	return e->coding[0] ? kof_unp_method_name(e->coding[0]) : "";
}

/*
 * One entry row, shared by the four archive printers so that a coded entry
 * looks the same in all of them.
 *
 * TWO THINGS HAVE TO BE SAID RATHER THAN ASSUMED, and both were wrong when each
 * printer had its own row.
 *
 * `size` IS WHAT COMES OUT, not what is in the file. For a stored entry those
 * are the same number; for a coded one they are not, and an ARJ listing that
 * printed the compressed length beside a name read as an archive of tiny files.
 * Every coded entry carries the decoded length in the low half of out_hint -
 * see KOF_UNP_LZX and KOF_UNP_LZHUF_ARJ - whatever the format.
 *
 * AND A SCATTERED ENTRY HAS NO OFFSET. Its bytes are not a range of the object
 * at all, so `off` is not a number to print; the dash is the honest answer
 * where a zero would read as the start of the file.
 */
static void print_entry_row(uint32_t i, const struct kof_entry *e, kof_buf buf,
			    int name_max)
{
	int n = e->name_len > (uint64_t)name_max ? name_max : (int)e->name_len;
	unsigned long long size = e->coding[0]
				? (unsigned long long)(e->out_hint & 0xffffffffu)
				: (unsigned long long)e->len;
	char off[32];

	if (e->flags & KOF_ENT_F_SCATTERED)
		snprintf(off, sizeof off, "off=-");
	else
		snprintf(off, sizeof off, "off=%llu",
			 (unsigned long long)e->off);

	printf("    [%3u] %-8s %-16s size=%-10llu %.*s\n", i,
	       e->coding[0] ? ent_coding(e) : "stored", off, size, n,
	       (const char *)buf.p + e->name_off);
}
static void print_cab(const void *v, const struct kof_obj_ctx *ctx, kof_buf buf)
{
	const struct kof_cab_info *c = v;
	uint32_t i, shown = 0;

	(void)ctx;

	printf("  version   %u.%u   set=0x%04x index=%u\n", c->ver_major,
	       c->ver_minor, c->set_id, c->cab_index);
	printf("  declared  %llu byte(s)   %u folder(s), %u file(s)\n",
	       (unsigned long long)c->declared_size, c->n_folders, c->n_files);
	printf("  files     %u openable, %u behind a coding, %u split across "
	       "blocks\n", c->n_entries, c->n_coded, c->n_split);
	for (i = 0; i < c->n_folders && i < 8u; i++) {
		char coding[24];

		if (c->folder[i].compress == KOF_CAB_C_LZX)
			snprintf(coding, sizeof coding, "LZX/%u",
				 c->folder[i].window);
		else
			snprintf(coding, sizeof coding, "%s",
				 c->folder[i].compress == KOF_CAB_C_NONE
					 ? "stored"
				 : c->folder[i].compress == KOF_CAB_C_MSZIP
					 ? "MSZIP"
					 : "Quantum");
		printf("    folder[%u] off=%-10llu blocks=%-5u %s\n", i,
		       (unsigned long long)c->folder[i].data_off,
		       c->folder[i].n_blocks, coding);
	}
	for (i = 0; i < c->n_entries && shown < 12u; i++, shown++)
		print_entry_row(i, &c->entry[i], buf, 48);
	if (c->n_entries > shown)
		printf("    ... %u more\n", c->n_entries - shown);
}

/*
 * ONE OF A SHELL LINK'S COUNTED STRINGS, AS TEXT.
 *
 * The bytes are UTF-16LE when the header says so, and this prints the ASCII
 * subset of them: a shortcut's arguments are a command line, and a command
 * line that matters is overwhelmingly ASCII even when the file is not. A
 * character outside it becomes '.', which is what the rest of this tool does
 * with a byte it will not vouch for.
 *
 * CLIPPED, because the whole point of an interesting one is that it is long -
 * an encoded payload in the arguments runs to kilobytes, and a terminal is not
 * where that gets read. The count is printed beside it so the clip is visible
 * rather than silent.
 */
static void print_lnk_str(const char *label, const struct kof_lnk_str *s,
			  int unicode, kof_buf buf, unsigned cap)
{
	uint64_t step = unicode ? 2u : 1u;
	uint64_t i, shown = 0;

	if (!s->chars || !s->len)
		return;
	printf("  %-9s %u char(s)  ", label, s->chars);
	for (i = 0; i + step <= s->len && shown < cap; i += step, shown++) {
		uint8_t c = buf.p[s->off + i];

		/* A UTF-16 unit whose high byte is set is outside what this
		 * prints; one dot for the character, not two. */
		if (unicode && buf.p[s->off + i + 1u])
			c = '.';
		putchar((c >= 0x20u && c < 0x7fu) ? (int)c : '.');
	}
	if (shown < s->chars)
		printf("...");
	printf("\n");
}

static void print_reg(const void *v, const struct kof_obj_ctx *ctx, kof_buf buf)
{
	const struct kof_reg_info *r = v;

	(void)ctx;
	(void)buf;

	printf("  script    %s\n",
	       (r->anomalies & KOF_REG_ANOM_OLD_FORMAT)
	       ? "REGEDIT4, the Windows 9x spelling"
	       : "Windows Registry Editor Version 5.00");
	/*
	 * THE DELETIONS ON THEIR OWN LINE, because n_deletes counts BOTH kinds
	 * - a "[-HKEY..." key and a "name"=- value - and attributing it to the
	 * keys said "2 keys, of which 2 remove something" about a file with
	 * one of each. The number is what the file removes; which of the two
	 * shapes each one was is what the KEYS and VALUES regions answer.
	 */
	printf("  keys      %u\n", r->n_keys);
	printf("  values    %u, %u of them binary\n", r->n_values, r->n_hex);
	if (r->n_deletes)
		printf("  removes   %u entr%s\n", r->n_deletes,
		       r->n_deletes == 1u ? "y" : "ies");
	if (r->hex_longest)
		printf("  longest   %llu byte(s) of hex text\n",
		       (unsigned long long)r->hex_longest);
}

static void print_lnk(const void *v, const struct kof_obj_ctx *ctx, kof_buf buf)
{
	const struct kof_lnk_info *k = v;
	int u = k->unicode != 0;

	(void)ctx;

	printf("  link      flags 0x%08x  show %u  hotkey 0x%04x%s\n",
	       k->flags, k->show_command, k->hotkey,
	       (k->flags & KOF_LNK_RUN_AS_USER) ? "  RUN AS USER" : "");
	printf("  target    %u byte(s) as the link remembers it, "
	       "attributes 0x%08x\n", k->target_size, k->attributes);
	if (k->idlist_len)
		printf("  idlist    %llu byte(s), not decoded\n",
		       (unsigned long long)k->idlist_len);
	if (k->info_len) {
		printf("  linkinfo  %llu byte(s), header %u%s%s\n",
		       (unsigned long long)k->info_len, k->info_hdr,
		       (k->info_flags & KOF_LNK_INFO_HAS_LOCAL) ? "  local" : "",
		       (k->info_flags & KOF_LNK_INFO_HAS_NET) ? "  network" : "");
		if (k->volume_serial || k->drive_type)
			printf("  volume    drive type %u  serial %08x\n",
			       k->drive_type, k->volume_serial);
		/*
		 * ANSI, EXPLICITLY, and not the header's unicode flag. That
		 * flag governs StringData; LinkInfo's own strings are ANSI
		 * unless the long header form names a unicode twin, which is
		 * printed as its own line when it is there.
		 */
		print_lnk_str("label", &k->vol_label, 0, buf, 64u);
		print_lnk_str("path", &k->local_path, 0, buf, 160u);
		print_lnk_str("suffix", &k->path_suffix, 0, buf, 96u);
		print_lnk_str("path16", &k->local_path_w, 1, buf, 160u);
		print_lnk_str("suffix16", &k->path_suffix_w, 1, buf, 96u);
		print_lnk_str("netname", &k->net_name, 0, buf, 160u);
	}

	/*
	 * IN THE ORDER THE FORMAT STORES THEM, which is also the order they
	 * were parsed - so a reader comparing this against a hex dump walks
	 * the file forwards.
	 */
	print_lnk_str("name", &k->name, u, buf, 64u);
	print_lnk_str("relpath", &k->relpath, u, buf, 96u);
	print_lnk_str("workdir", &k->workdir, u, buf, 96u);
	print_lnk_str("arguments", &k->args, u, buf, 160u);
	print_lnk_str("icon", &k->icon, u, buf, 96u);

	if (k->n_extra) {
		/*
		 * NAMED, because "6 blocks" and "6 blocks one of which is an
		 * environment target" are different sentences and only the
		 * second one is worth a person's time.
		 */
		static const struct {
			uint32_t bit;
			const char *name;
		} blk[] = {
			{ KOF_LNK_BLK_ENV,        "env" },
			{ KOF_LNK_BLK_CONSOLE,    "console" },
			{ KOF_LNK_BLK_TRACKER,    "tracker" },
			{ KOF_LNK_BLK_CONSOLE_FE, "console-fe" },
			{ KOF_LNK_BLK_SPECIAL,    "special-folder" },
			{ KOF_LNK_BLK_DARWIN,     "darwin" },
			{ KOF_LNK_BLK_ICONENV,    "icon-env" },
			{ KOF_LNK_BLK_SHIM,       "shim" },
			{ KOF_LNK_BLK_PROPSTORE,  "property-store" },
			{ KOF_LNK_BLK_KNOWNFLDR,  "known-folder" },
			{ KOF_LNK_BLK_VISTAIDL,   "vista-idlist" },
			{ KOF_LNK_BLK_UNKNOWN,    "unassigned" }
		};
		unsigned i;

		printf("  extra     %u block(s), %llu byte(s):", k->n_extra,
		       (unsigned long long)k->extra_len);
		for (i = 0; i < sizeof blk / sizeof blk[0]; i++)
			if (k->blocks & blk[i].bit)
				printf(" %s", blk[i].name);
		printf("\n");

		print_lnk_str("envpath", &k->env_target, 0, buf, 160u);
		print_lnk_str("envpath16", &k->env_target_w, 1, buf, 160u);
		print_lnk_str("iconenv", &k->icon_env, 0, buf, 160u);
		print_lnk_str("iconenv16", &k->icon_env_w, 1, buf, 160u);
		print_lnk_str("madeon", &k->machine_id, 0, buf, 32u);
	}
}

static void print_lha(const void *v, const struct kof_obj_ctx *ctx, kof_buf buf)
{
	const struct kof_lha_info *l = v;
	uint32_t i, shown = 0;

	(void)ctx;

	printf("  header    level %u\n", l->level);
	printf("  entries   %u openable, %u behind a coding, %u director%s\n",
	       l->n_entries, l->n_coded, l->n_dirs,
	       l->n_dirs == 1u ? "y" : "ies");
	for (i = 0; i < l->n_entries && shown < 12u; i++, shown++)
		print_entry_row(i, &l->entry[i], buf, 48);
	if (l->n_entries > shown)
		printf("    ... %u more\n", l->n_entries - shown);
}

static void print_arj(const void *v, const struct kof_obj_ctx *ctx, kof_buf buf)
{
	const struct kof_arj_info *a = v;
	uint32_t i, shown = 0;

	(void)ctx;

	printf("  archiver  version %u, needs %u   host os %u\n",
	       a->archiver_ver, a->min_ver, a->host_os);
	printf("  entries   %u openable, %u behind a coding, %u director%s\n",
	       a->n_entries, a->n_coded, a->n_dirs,
	       a->n_dirs == 1u ? "y" : "ies");
	for (i = 0; i < a->n_entries && shown < 12u; i++, shown++)
		print_entry_row(i, &a->entry[i], buf, 48);
	if (a->n_entries > shown)
		printf("    ... %u more\n", a->n_entries - shown);
}

/*
 * The directory, the compressed section, and how much of each this build
 * reaches.
 *
 * THE LZX LINE IS THE ONE THAT MATTERS ON A REAL HELP FILE. Nearly every page
 * of one is in the coded section, so "27 compressed" without the stream's own
 * numbers beside it says only that the document is compressed. What decides
 * whether those pages are reachable is the window, the restart interval and the
 * reset table - and n_unreachable is what is left when any of the three is
 * missing.
 */
static void print_chm(const void *v, const struct kof_obj_ctx *ctx, kof_buf buf)
{
	const struct kof_chm_info *c = v;
	uint32_t i, shown = 0;

	(void)ctx;

	printf("  version   ITSF %u   lang=0x%04x\n", c->itsf_version,
	       c->lang_id);
	printf("  directory off=%llu len=%llu   %u chunk(s) of %u\n",
	       (unsigned long long)c->dir_off, (unsigned long long)c->dir_len,
	       c->n_chunks, c->chunk_size);
	printf("  content   off=%llu\n", (unsigned long long)c->content_off);
	printf("  entries   %u openable, %u compressed, %u internal\n",
	       c->n_entries, c->n_compressed, c->n_special);
	if (c->lzx_window_bits || c->n_compressed)
		printf("  lzx       window 2^%u   restart every %u frame(s) "
		       "of %llu   %u reset row(s)\n"
		       "            stream off=%llu len=%llu -> %llu byte(s)"
		       "   %u entr%s unreachable\n",
		       c->lzx_window_bits, c->lzx_reset_interval,
		       (unsigned long long)c->lzx_frame, c->n_reset,
		       (unsigned long long)c->lzx_off,
		       (unsigned long long)c->lzx_len,
		       (unsigned long long)c->lzx_uncomp_len,
		       c->n_unreachable, c->n_unreachable == 1u ? "y" : "ies");
	for (i = 0; i < c->n_entries && shown < 12u; i++, shown++)
		print_entry_row(i, &c->entry[i], buf, 60);
	if (c->n_entries > shown)
		printf("    ... %u more\n", c->n_entries - shown);
}

static void print_bz2(const void *v, const struct kof_obj_ctx *ctx, kof_buf buf)
{
	const struct kof_bz2_info *b = v;

	(void)ctx;
	(void)buf;

	printf("  level     %u   block up to %u byte(s)\n",
	       (unsigned)b->level, b->block_size);
	printf("  coded     off=%llu len=%llu\n",
	       (unsigned long long)b->data_off, (unsigned long long)b->data_len);
}

static void print_xz(const void *v, const struct kof_obj_ctx *ctx, kof_buf buf)
{
	const struct kof_xz_info *x = v;
	uint32_t i, shown = 0;

	(void)ctx;
	(void)buf;

	printf("  check     %u (%u byte(s))   %u block(s)", x->check,
	       x->check_len, x->n_blocks);
	if (x->declared_blocks != x->n_blocks)
		printf(" (%u declared)", x->declared_blocks);
	printf("\n");
	printf("  index     off=%llu len=%llu   footer=%llu\n",
	       (unsigned long long)x->index_off, (unsigned long long)x->index_len,
	       (unsigned long long)x->footer_off);
	printf("  declared  packed=%llu unpacked=%llu",
	       (unsigned long long)x->total_comp,
	       (unsigned long long)x->total_uncomp);
	if (x->total_comp)
		printf("   ratio %.1fx",
		       (double)x->total_uncomp / (double)x->total_comp);
	printf("\n");

	for (i = 0; i < x->n_blocks; i++) {
		const struct kof_xz_block *b = &x->block[i];

		if (shown >= ZIP_SHOW && !b->suspicious)
			continue;
		shown++;
		printf("    [%3u] filter=0x%02x x%u  %9llu -> %-9llu @%llu", i,
		       b->filter, b->n_filters, (unsigned long long)b->comp_size,
		       (unsigned long long)b->uncomp_size,
		       (unsigned long long)b->data_off);
		if (b->suspicious & KOF_XZ_BLK_CHAIN)
			kex_note_warn("a filter runs in front of the coder");
		if (b->suspicious & KOF_XZ_BLK_PAST_EOF)
			kex_note_bad("data runs past the end");
		if (b->suspicious & KOF_XZ_BLK_RATIO)
			kex_note_bad("declared expansion is absurd");
		printf("\n");
	}
	if (x->n_blocks > shown)
		printf("    ... %u more\n", x->n_blocks - shown);
}


/* What an RTF carries, which is embedded objects and how hard it worked to hide
 * where they start. */
static void print_rtf(const void *v, const struct kof_obj_ctx *ctx, kof_buf buf)
{
	const struct kof_rtf_info *r = v;
	uint32_t i;

	(void)ctx;

	printf("  groups    depth %u   %u control word(s)   %u \\bin run(s)\n",
	       r->max_depth, r->n_controls, r->n_bin);
	printf("  objects   %u embedded\n", r->n_objects);
	for (i = 0; i < r->n_objects; i++) {
		const struct kof_rtf_object *o = &r->obj[i];

		printf("    [%2u] hex %llu byte(s) at %llu -> %llu decoded", i,
		       (unsigned long long)o->data_len,
		       (unsigned long long)o->data_off,
		       (unsigned long long)o->hex_bytes);
		if (o->class_len) {
			printf("  class=");
			print_entry_name(buf, o->class_off, o->class_len, 32u);
		}
		if (o->suspicious & KOF_RTF_OBJ_OLE)
			kex_note_note("a compound file");
		if (o->suspicious & KOF_RTF_OBJ_OLE1)
			kex_note_note("an OLE1 package");
		if (o->suspicious & KOF_RTF_OBJ_UPDATE)
			kex_note_bad("OPENS WITHOUT BEING CLICKED");
		if (o->suspicious & KOF_RTF_OBJ_BAD_HEX)
			kex_note_bad("the hex does not pair up");
		printf("\n");
	}
}


static void print_pdf(const void *v, const struct kof_obj_ctx *ctx, kof_buf buf)
{
	const struct kof_pdf_info *p = v;
	uint32_t i, shown = 0;

	(void)ctx; (void)buf;
	printf("  version   PDF %u.%u   header at %llu\n", p->ver_major,
	       p->ver_minor, (unsigned long long)p->header_off);
	printf("  objects   %u (%u with a stream)   startxref=%llu\n",
	       p->n_objects, p->n_streams, (unsigned long long)p->startxref);
	for (i = 0; i < p->n_objects && shown < 12u; i++) {
		const struct kof_pdf_object *o = &p->object[i];

		if (!o->flags && !o->filters)
			continue;
		printf("    [%3u] %u %u obj  dict=%llu+%llu stream=%llu+%llu"
		       "  flags=0x%x filters=0x%x\n", i, o->num, o->gen,
		       (unsigned long long)o->dict_off,
		       (unsigned long long)o->dict_len,
		       (unsigned long long)o->stream_off,
		       (unsigned long long)o->stream_len, o->flags, o->filters);
		shown++;
	}
}





/*
 * The printer for a format, chosen by what the parse said the object is.
 *
 * A switch rather than a column in the shared table: the table describes an
 * object, and how this particular front end draws one is not a property of the
 * object. It is also the whole of what stayed behind when the table moved.
 */
void kex_print_view(uint8_t format, const void *view,
		       const struct kof_obj_ctx *ctx, kof_buf buf)
{
	switch (format) {
	case KOF_FMT_ELF:    kex_print_elf(view, ctx, buf);    break;
	case KOF_FMT_PE:     kex_print_pe(view, ctx, buf);     break;
	case KOF_FMT_GZIP:   print_gzip(view, ctx, buf);   break;
	case KOF_FMT_DOCOLE: print_docole(view, ctx, buf); break;
	case KOF_FMT_ZIP:
	case KOF_FMT_DOCZIP: print_zip(view, ctx, buf);    break;
	case KOF_FMT_TAR:    print_tar(view, ctx, buf);    break;
	case KOF_FMT_7Z:     print_7z(view, ctx, buf);     break;
	case KOF_FMT_RAR:    print_rar(view, ctx, buf);    break;
	case KOF_FMT_XZ:     print_xz(view, ctx, buf);     break;
	case KOF_FMT_BZIP2:  print_bz2(view, ctx, buf);    break;
	case KOF_FMT_CHM:    print_chm(view, ctx, buf);    break;
	case KOF_FMT_CAB:    print_cab(view, ctx, buf);    break;
	case KOF_FMT_LHA:    print_lha(view, ctx, buf);    break;
	case KOF_FMT_ARJ:    print_arj(view, ctx, buf);    break;
	case KOF_FMT_LNK:    print_lnk(view, ctx, buf);    break;
	case KOF_FMT_REG:    print_reg(view, ctx, buf);    break;
	case KOF_FMT_RTF:    print_rtf(view, ctx, buf);    break;
	case KOF_FMT_PDF:    print_pdf(view, ctx, buf);    break;
	default:                                           break;
	}
}

