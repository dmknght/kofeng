/*
 * rcpfile.c - one file as `scp` put it on the wire.
 *
 * `scp` does not send a file, it speaks a protocol at the far end's `scp -t`,
 * and the protocol is line oriented and plain:
 *
 *     C0755 4745 a1FVFdki\n     mode, length, name
 *     <4745 bytes>              the file
 *     \0                        the sink's acknowledgement
 *
 * A capture of that conversation is a file on disk, and three samples in this
 * corpus are exactly one: twenty bytes of header, a bash script, a NUL. Read as
 * a whole they are nothing - the shebang is not on line one, no sniff claims
 * them, and all three came back `unrecognised` with no parse, no regions and no
 * normalised view. Read as what they are they are a shell script in a one-entry
 * container.
 *
 * A CONTAINER, AND THE WORD IS EXACT. The header IS the table: it declares
 * where the member starts and how long it is, which is the whole of what
 * KOF_UNP_CONTAINER means. Nothing here is carved, searched for or guessed at.
 *
 * WHAT MAKES IT SAFE IS ARITHMETIC, NOT A MAGIC NUMBER. `C` followed by four
 * octal digits is a shape a text file could reach by accident; a declared
 * length that lands exactly on the end of the object is not. The header and the
 * member have to account for every byte, give or take the one NUL the sink
 * writes back - and that is checked before anything is produced. Measured over
 * /usr/bin and /usr/lib: nothing begins with `C` and four octal digits at all.
 * Over the three corpora: three files do, and all three balance.
 *
 * ONE `C` RECORD AND NOTHING ELSE. The protocol also carries `D` for a
 * directory, `T` for timestamps and any number of records in sequence, and none
 * of those can be checked this way - a stream of them has no single length that
 * has to come out right, so the one test that makes this honest does not apply.
 * They are left alone rather than half-read.
 */

#include <kofmod/kofsig.h>

KOF_UNPACK_KIND(KOF_UNP_CONTAINER);

/* Nothing declared this file's format, which is the point - it is the shape
 * that makes an object unreadable. */
KOF_TARGET_FORMAT(KOF_FMT_UNKNOWN);

/* "C0000 1 x\n" is nine; below that there is no record. */
#define RCP_MIN      9u
/* A length the protocol could state, bounded so the parse cannot run away on a
 * digit run: 12 digits is a terabyte and more than any object here. */
#define RCP_DIG_MAX 12u
/* The sink's own limit on a path component. */
#define RCP_NAME_MAX 255u

static int octal(uint8_t c) { return c >= '0' && c <= '7'; }
static int digit(uint8_t c) { return c >= '0' && c <= '9'; }

void kof_unpack(const struct kof_obj_ctx *ctx)
{
	uint64_t i, size = 0, name_off, hdr;
	uint32_t nd = 0;

	if (ctx->obj_size < RCP_MIN)
		return;

	/* C<mode> - four octal digits and the space after them. */
	if (kof_u8(0) != 'C')
		return;
	for (i = 1; i <= 4; i++)
		if (!octal((uint8_t)kof_u8(i)))
			return;
	if (kof_u8(5) != ' ')
		return;

	/* <length>, in decimal, then one space. */
	for (i = 6; i < ctx->obj_size && nd < RCP_DIG_MAX; i++, nd++) {
		uint8_t c = (uint8_t)kof_u8(i);

		if (!digit(c))
			break;
		size = size * 10u + (uint64_t)(c - '0');
	}
	if (!nd || i >= ctx->obj_size || kof_u8(i) != ' ')
		return;
	name_off = ++i;

	/*
	 * <name>, to the newline. A path separator in it would mean the sink
	 * was asked to write outside the directory it was given, which the
	 * protocol forbids and this does not read as a name.
	 */
	while (i < ctx->obj_size && i - name_off <= RCP_NAME_MAX) {
		uint8_t c = (uint8_t)kof_u8(i);

		if (c == '\n')
			break;
		if (c == '/' || c == 0)
			return;
		i++;
	}
	if (i >= ctx->obj_size || kof_u8(i) != '\n' || i == name_off)
		return;
	hdr = i + 1u;

	/*
	 * AND IT HAS TO BALANCE. Everything above is a shape; this is the
	 * evidence. The member ends where the object ends, or one byte short
	 * of it where the sink's acknowledging NUL was captured too.
	 */
	if (!size || (hdr + size != ctx->obj_size &&
		      hdr + size + 1u != ctx->obj_size))
		return;

	kof_name_next(name_off, i - name_off);
	if (!kof_child_window(hdr, size))
		KOF_UNP_BROKEN(KOF_UNP_LIMIT);
}
