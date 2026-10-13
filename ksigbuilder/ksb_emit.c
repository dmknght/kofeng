/*
 * ksb_emit.c - --extract, the output: the generated header and the record
 *    lines for one declaration.
 */

#include "ksb.h"

/*
 * Emit the header the module compiles against: one identifier per declared string.
 *
 * No pattern bytes. They used to be emitted as arrays that landed in the blob's
 * .rodata, because the module did its own searching; now the host searches, so the
 * bytes belong in the record beside the blob and the module only needs the index.
 * The blob got smaller and stopped carrying the literals it looks for.
 */
/*
 * THE MARKER, INSIDE A C COMMENT THAT IT MUST NOT BE ABLE TO CLOSE.
 *
 * The bytes were written straight into a comment, and a marker is allowed to
 * contain anything printable - including the two characters that END one. A
 * marker holding a block-comment terminator is an ordinary thing to cut out of
 * a shell, and
 * declaring it emitted a header whose comment stopped in the middle of the
 * string; the compiler then read the rest as code and the build died on a
 * missing quote, pointing at a generated file the researcher never wrote.
 *
 * The slash is what terminates, so the slash is what is broken. A backslash
 * before it means nothing inside a comment, so the text still reads as itself.
 *
 * Control bytes are spelled out for a second reason: a marker holding a newline
 * would otherwise put the rest of itself on another line of the header, where
 * it is no longer inside the comment at all.
 */
static void put_comment(FILE *out, const uint8_t *b, uint32_t n)
{
	uint32_t i;

	for (i = 0; i < n; i++) {
		uint8_t c = b[i];

		if (c == '/' && i && b[i - 1u] == '*') {
			fputs("\\/", out);
			continue;
		}
		if (c == '\n') { fputs("\\n", out); continue; }
		if (c == '\r') { fputs("\\r", out); continue; }
		if (c == '\t') { fputs("\\t", out); continue; }
		fputc(c < 0x20u || c > 0x7eu ? '.' : (int)c, out);
	}
}

void ksb_emit_str_id(FILE *out, const struct pat *p, int idx)
{
	fprintf(out, "/* line %d: \"", p->line);
	put_comment(out, p->wide ? (const uint8_t *)p->shown : p->bytes,
		    p->wide ? (uint32_t)strlen(p->shown) : p->len);
	fprintf(out, "\"%s%s%s */\n",
		p->wide ? " wide" : "",
		p->icase ? " icase" : "",
		p->fullword ? " fullword" : "");
	fprintf(out, "#define kof_strid_%s %d\n\n", p->name, idx);
}

void ksb_emit_rng_id(FILE *out, const struct rng *r, int idx)
{
	fprintf(out, "/* line %d: range mask 0x%x */\n", r->line, r->mask);
	fprintf(out, "#define kof_rangeid_%s %d\n\n", r->name, idx);
}

/*
 * Emit the records the packer reads.
 *
 * Tab separated so they are readable and diffable; the fields are the ones needed
 * and nothing else. The literal is last because it is the only field that can
 * contain anything, so nothing has to be escaped to keep the columns parseable.
 */
void ksb_emit_str_record(FILE *out, const struct pat *p, int idx)
{
	uint32_t i;

	/*
	 * A compiled hex program is arbitrary bytes, so it cannot go in the column
	 * a literal uses - a newline in it would end the row. Hex digits cost twice
	 * the space in a file that exists for one build step and are readable when
	 * something goes wrong, which is what the sidecar is for.
	 */
	if (p->kind == KOF_STR_HEX) {
		/* h <idx> <icase> <word> <len> <program in hex>. The two option
		 * columns used to be absent, so a hex pattern's case and word
		 * choices were read out of the source and dropped here - the
		 * declaration compiled, the options were printed at build time,
		 * and nothing downstream ever saw them. */
		fprintf(out, "h\t%d\t%d\t%d\t%u\t", idx, p->icase,
			p->fullword, p->len);
		for (i = 0; i < p->len; i++)
			fprintf(out, "%02x", p->bytes[i]);
		fputc('\n', out);
		return;
	}
	/*
	 * A LITERAL THAT IS NOT TEXT goes in hex too, and keeps its options.
	 *
	 * The 's' row puts the bytes last so nothing in them needs escaping -
	 * which holds only while they are printable. A wide pattern is the
	 * literal with zero high bytes interleaved, so the row ended at the
	 * first character and the reader's own length check refused the build:
	 * "string of declared length 28 does not match its literal". Loud, and
	 * still a build that cannot produce a wide signature.
	 *
	 * 'h' is not the answer either - it means a compiled hex PROGRAM, and
	 * reading a literal back as one would change what the matcher does with
	 * it. So 'w': a literal, in hex, with the icase and fullword columns an
	 * 'h' row has no room for.
	 *
	 * Chosen by what the bytes ARE, not by which macro was used. Anything
	 * that cannot survive a text column takes this row, so a future pattern
	 * with a control byte in it works without anyone remembering this.
	 */
	{
		int text_safe = 1;

		for (i = 0; i < p->len; i++) {
			uint8_t c = p->bytes[i];

			if (c < 0x20u || c == 0x7fu) {
				text_safe = 0;
				break;
			}
		}
		if (!text_safe) {
			/* The wide column belongs on this row and only this
			 * row: a widened pattern has a zero above every
			 * character, so it is never text-safe and can never
			 * take the 's' path. */
			fprintf(out, "w\t%d\t%d\t%d\t%d\t%u\t", idx,
				p->icase, p->fullword, p->wide, p->len);
			for (i = 0; i < p->len; i++)
				fprintf(out, "%02x", p->bytes[i]);
			fputc('\n', out);
			return;
		}
	}
	fprintf(out, "s\t%d\t%d\t%d\t%u\t%.*s\n", idx,
		p->icase, p->fullword, p->len, (int)p->len,
		(const char *)p->bytes);
}

void ksb_emit_rng_record(FILE *out, const struct rng *r, int idx)
{
	fprintf(out, "r\t%d\t%u\n", idx, r->mask);
}

void ksb_emit_blk_id(FILE *out, const struct blk *b, int idx)
{
	fprintf(out, "/* line %d: block, region mask 0x%x, norm %u, %u hash(es) */\n",
		b->line, b->mask, b->norm, b->n_hash);
	fprintf(out, "#define kof_blockid_%s %d\n\n", b->name, idx);
}

/* b <id> <mask> <norm> <side> <n> <hashes in hex, no separator> */
void ksb_emit_blk_record(FILE *out, const struct blk *b, int idx)
{
	uint32_t i;

	/* `side` sits before the count rather than after the hashes, so the
	 * reader stays a fixed run of numeric fields followed by one blob. */
	fprintf(out, "b\t%d\t%u\t%u\t%u\t%u\t", idx, b->mask, b->norm,
		b->side, b->n_hash);
	for (i = 0; i < b->n_hash; i++)
		fprintf(out, "%08x", b->hash[i]);
	fputc('\n', out);
}
