/*
 * decomp/textcode - the text codings of kuncoat: Ascii85, hex and the RLE of a PDF stream. The first input byte picks
 * the function (0 a85, 1 ahx, 2 rle), so the seeds of the three share one row and a mutation can move between them.
 * Held: the status is in the enum, produced <= cap, a string that decodes completely has not been cut by the buffer
 * (OVER_BUDGET says so), the bytes before the output buffer are untouched, the receiver is not called after a refusal.
 */
#include <uncoat.h>

#include "../../lib/fuzz_drv.h"

static void add(struct fz_corpus *c, const char *name, unsigned sel, const char *text, size_t n)
{
	uint8_t buf[512];

	buf[0] = (uint8_t)sel;
	memcpy(buf + 1, text, n);
	fz_corpus_add(c, name, buf, n + 1u);
}

static void seeds(struct fz_corpus *c)
{
	static const char a85[] = "87cURD]i,\"Ebo80~>";
	static const char a85z[] = "<~z!!*-'\"9eu7#RLhG$k3[W&.oNg'GVB\"(`=52*$$(B+<_pR,UFcb-n-Vr/1iJ-0JP==1c70M3&s#]4?Ykm5X@_(6q'R884cEH9MJ8X:f1+h<)lt#=BSg3>[:ZC?t!MSA7]@cBPD3sCi+'.E9mH~>";
	static const char ahx[] = "48656c6c6f2c20776f726c64>";
	static const char ahx2[] = "48 65 6C 6c\n6F 2c 2 0>";
	static const char rle[] = "\x04Hello\xfdz\x80";

	add(c, "a85", 0, a85, sizeof a85 - 1u);
	add(c, "a85-long", 0, a85z, sizeof a85z - 1u);
	add(c, "ahx", 1, ahx, sizeof ahx - 1u);
	add(c, "ahx-ws", 1, ahx2, sizeof ahx2 - 1u);
	add(c, "rle", 2, rle, sizeof rle - 1u);
}

static const char *const dict[] = { "~>", "<~", "z", ">", "\x80", NULL };

static int run(struct fz_ctx *c, const uint8_t *in, size_t n)
{
	enum kuncoat_status r = KUNCOAT_BAD_ARG;
	uint64_t produced = 0;
	unsigned sel = n ? in[0] % 3u : 0u;
	const uint8_t *body = n ? in + 1 : in;
	uint64_t bn = n ? n - 1u : 0;

	switch (sel) {
	case 0: r = kuncoat_a85_decode(body, bn, c->out, c->cap, &produced); break;
	case 1: r = kuncoat_ahx_decode(body, bn, c->out, c->cap, &produced); break;
	default: r = kuncoat_rle_decode(body, bn, c->sink_fn, c->sink_user, &produced); break;
	}
	FZ_CHECK(c, (unsigned)r <= (unsigned)KUNCOAT_BAD_ARG, "status outside the enum");
	if (sel < 2) {
		FZ_CHECK(c, produced <= c->cap, "produced more than the buffer");
		if (r == KUNCOAT_OK)
			FZ_CHECK(c, produced <= c->cap, "OK with an overfull buffer");
	} else {
		FZ_CHECK(c, produced >= c->sink.total, "sink took more than produced");
		FZ_CHECK(c, !c->refused || r == KUNCOAT_STOPPED, "a refusing sink did not end in STOPPED");
	}
	fz_digest(c, (uint64_t)r ^ produced << 3 ^ (uint64_t)sel << 60);
	return (int)r;
}

FZ_ADAPTER(textcode, .name = "kuncoat/textcode", .covers = "kuncoat_a85_decode kuncoat_ahx_decode kuncoat_rle_decode", .shape = FZ_BYTES,
	   .seeds = seeds, .dict = dict, .run = run);
