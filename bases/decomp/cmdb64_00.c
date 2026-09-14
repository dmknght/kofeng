/*
 * cmdb64_00.c - the base64 payload of a shell command stored inside a binary.
 *
 * WHAT THIS IS FOR. A dropper does not need a script file. Mirai and everything
 * shaped like it carry the whole thing as one C string in .rodata:
 *
 *     echo <base64> | base64 -d | sh
 *
 * The string is right there and the engine could already see its bytes, but
 * what it could see was the ENCODED form - so every signature written against
 * what the command actually does was written against something that is not in
 * the file. The decoded half is where the addresses, the paths and the second
 * stage are.
 *
 * WHY THE ANCHOR IS THE DECODER AND NOT THE PAYLOAD.
 *
 * Hunting for base64-looking runs does not work and is not worth trying. The
 * base64 alphabet is also the alphabet of identifiers: `ThisIsAVariableName` is
 * a valid base64 run, and so is most of a symbol table. A scan for runs in a
 * binary finds thousands of them and every one is a guess about where it starts
 * and where it ends.
 *
 * So the decoder names itself. `base64 -d` is nine concrete bytes - well past
 * the four the presence set keys on - and a file that contains it is a file
 * that means to decode something. That is the anchor, and the anchor is the
 * only thing searched for.
 *
 * WHY THE EXTENT IS FREE, WHICH IS THE POINT.
 *
 * In a source file, finding where an encoded literal begins needs a lexer. In a
 * BINARY it needs nothing. The payload is the run that ENDS AT THE PIPE: step
 * back over the separator, and every byte before it that is in the base64
 * alphabet belongs to the payload. The first byte that is not ends it.
 *
 * There is no guessing anywhere in this module. The anchor is exact, the
 * separator is exact, and the run's far end is exact. What used to stand here
 * was a walk to the C string's NUL followed by a hunt for the LONGEST base64
 * run inside it - two passes over the whole string to answer a question the
 * bytes next to the anchor answer directly, and a question that was subtly the
 * wrong one: a longer run elsewhere in the same command could win over the one
 * that is actually being piped.
 *
 * The string boundary still matters for one reason - a run must not be a window
 * onto bytes belonging to something else - and that is checked by asking what
 * is immediately BEFORE the run rather than by walking to find out. A payload
 * is an argument, so it follows a NUL, a space, a quote or a bracket.
 *
 * WHAT IT DELIBERATELY DOES NOT DO. It does not decide anything. The decoded
 * bytes become a CHILD OBJECT and the engine scans them like any other object -
 * so a payload that is an ELF is identified as one, a payload that is another
 * shell command comes back here, and a payload that is nothing interesting
 * costs a few kilobytes and no verdict. Extraction is the whole job; see
 * KOF_LVL_ACT for the same split drawn on the heuristic side.
 *
 * NO TABLES AND NO HELPERS, and that is a constraint rather than a style. A
 * module is linked to a flat blob that must carry no .rodata and no
 * relocations - see ksigbuilder's --image checks - so a 64-byte decode table
 * would be storage this cannot have. The alphabet is therefore computed with
 * comparisons, which costs a handful of instructions per character and is the
 * only form that survives the link.
 */

#include <kofmod/kofsig.h>

KOF_TARGET_FORMAT(KOF_FMT_ELF);

/*
 * A CONTAINER, not a packer. The binary hid nothing about itself - it is a
 * perfectly ordinary ELF that happens to carry a command, the way a zip carries
 * a file. A heuristic that weighs "this object was packed" must not weigh this,
 * or every dropper-shaped string turns into evidence of packing.
 */
KOF_UNPACK_KIND(KOF_UNP_CONTAINER);

/*
 * The spellings of the decoder that actually appear. Each is its own declared
 * string rather than one pattern with wildcards, because the presence set keys
 * on concrete bytes and every one of these has nine or more - a wildcard in the
 * middle would trade that away for nothing.
 *
 * `base64 -d` is a prefix of `base64 -di`, so the shorter one finds both and
 * the longer is not declared. `--decode` and the macOS `-D` are separate
 * spellings that share no prefix with it.
 */
KOF_DEFINE_STR(a_d,   "base64 -d",       KOF_CASE_EXACT, KOF_WORD_SUBSTRING);
KOF_DEFINE_STR(a_dec, "base64 --decode", KOF_CASE_EXACT, KOF_WORD_SUBSTRING);
KOF_DEFINE_STR(a_big, "base64 -D",       KOF_CASE_EXACT, KOF_WORD_SUBSTRING);

/*
 * How far back a separator run may reach between the payload and the decoder.
 * "  |  " is five; anything longer than this is not a pipeline, it is two
 * unrelated things that happen to be near each other.
 */
#define SEP_MAX      8u

/* The longest payload walked back over. Past every measured dropper one-liner
 * and small enough that a hostile file cannot make the walk expensive by
 * putting the anchor after a megabyte of printable bytes. */
#define PAY_MAX      8192u

/* Below this a run is not a payload. Sixteen characters decode to twelve
 * bytes, which is shorter than any second stage worth extracting and is about
 * where ordinary words stop being mistakable for one. */
#define RUN_MIN      16u

/* What one pass will produce. A command carries one payload; a file with more
 * anchors than this is doing something other than dropping, and the cap is what
 * keeps a crafted file from turning one scan into thousands of children. */
#define MAX_PAYLOAD  8u

/* The decode buffer. Emitted in full chunks, so the payload may be any size -
 * this is how much of it is held at once. */
#define OUT_CHUNK    1024u

void kof_unpack(const struct kof_obj_ctx *ctx)
{
	uint64_t next[3];
	uint32_t made = 0, k;

	if (!ctx->obj_size)
		return;

	/*
	 * EACH SPELLING SEARCHED ONCE, NOT ONCE PER PAYLOAD.
	 *
	 * The first version asked all three where they were on every pass, so a
	 * file with eight anchors paid twenty-four searches of the object - and
	 * two thirds of them re-found a string that had not moved. Their
	 * positions are kept instead, the nearest is taken, and only the one
	 * that was consumed is searched again. Three searches plus one per
	 * payload, against three per payload.
	 */
	next[0] = kof_find_str_where(0, ctx->obj_size, a_d);
	next[1] = kof_find_str_where(0, ctx->obj_size, a_dec);
	next[2] = kof_find_str_where(0, ctx->obj_size, a_big);

	while (made < MAX_PAYLOAD) {
		uint64_t pos = KOF_BROKEN, run_end, run_beg, i;
		uint32_t which = 0;
		uint8_t  out[OUT_CHUNK];
		uint32_t n_out = 0, acc = 0, have = 0;
		uint8_t  before;
		int      piped;

		for (k = 0; k < 3u; k++)
			if (next[k] != KOF_BROKEN &&
			    (pos == KOF_BROKEN || next[k] < pos)) {
				pos = next[k];
				which = k;
			}
		if (pos == KOF_BROKEN)
			return;
		/*
		 * Only the spelling that was taken needs looking for again.
		 *
		 * Three branches rather than one call with the string chosen
		 * at run time, because kof_find_str_where pastes the string's
		 * name into an id at BUILD time - the pattern bytes are in the
		 * database, not in this blob, so which string is being asked
		 * about cannot be a variable.
		 */
		{
			uint64_t at = pos + 1u;
			uint64_t room = at < ctx->obj_size
					? ctx->obj_size - at : 0;

			if (!room)
				next[which] = KOF_BROKEN;
			else if (which == 0)
				next[0] = kof_find_str_where(at, room, a_d);
			else if (which == 1)
				next[1] = kof_find_str_where(at, room, a_dec);
			else
				next[2] = kof_find_str_where(at, room, a_big);
		}

		/*
		 * BACK OVER THE PIPE, THEN BACK OVER THE PAYLOAD - one walk,
		 * and it is as long as the payload rather than as long as the
		 * string.
		 *
		 * The first version found the whole C string first (up to 8 KB
		 * backwards) and then scanned it forwards again looking for
		 * the LONGEST base64 run in it. Two passes over the string for
		 * a question that is answered by the bytes immediately before
		 * the anchor: in `echo <payload> | base64 -d` the payload is
		 * the run that ENDS at the pipe, and longest-in-the-string was
		 * a different question that happens to have the same answer
		 * most of the time. Nearest is both cheaper and more precise -
		 * a longer run elsewhere in the same command can no longer win.
		 */
		run_end = pos;
		piped = 0;
		for (i = 0; i < SEP_MAX && run_end > 0; i++) {
			uint8_t c = kof_u8(run_end - 1u);

			if (c == '|' || c == '<' || c == '>')
				piped = 1;
			else if (c != ' ' && c != '\t' && c != ')' &&
				 c != '"' && c != '\'')
				break;
			run_end--;
		}
		/*
		 * THE DECODER'S INPUT HAS TO COME FROM THE RUN, and a space
		 * does not say that.
		 *
		 * `base64 -d` reads stdin, so something must be PIPED or
		 * REDIRECTED into it; a bare space in front means its input is
		 * a file argument or comes from somewhere else entirely, and
		 * the bytes before it are just the previous word. Measured on
		 * a test carrying four shapes: without this,
		 * "ThisIsALongIdentifierLikeString base64 -d" decoded to
		 * twenty-three bytes of noise and was handed back as a
		 * recovered payload.
		 *
		 * The quotes are separators rather than terminators for the
		 * other half of that test: `echo "<payload>" | base64 -d` is
		 * the Mirai shape, and the closing quote sits between the
		 * payload and the pipe. Stopping at it found a run of length
		 * zero and dropped the one case this module exists for.
		 */
		if (!piped)
			continue;

		run_beg = run_end;
		for (i = 0; i < PAY_MAX && run_beg > 0; i++) {
			uint8_t c = kof_u8(run_beg - 1u);

			if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
			    (c >= '0' && c <= '9') || c == '+' || c == '/' ||
			    c == '=' || c == '\n' || c == '\r')
				run_beg--;
			else
				break;
		}
		/*
		 * PADDING ONLY EVER COMES LAST, so an `=` with a real
		 * character after it is a SEPARATOR and the payload starts
		 * after the last one.
		 *
		 * The walk above takes `=` as part of the alphabet, because a
		 * payload ends in it. That makes `VAR=<payload> | base64 -d`
		 * walk back through the `=` and into the variable's name - and
		 * the name is base64 characters too, so nothing stops it. Every
		 * group is then shifted and the payload decodes to noise.
		 *
		 * Not a guess: base64 has no `=` except at the end, so one in
		 * the middle belongs to whatever wrote it there.
		 */
		for (i = run_beg; i + 1u < run_end; i++)
			if (kof_u8(i) == '=' && kof_u8(i + 1u) != '=')
				run_beg = i + 1u;

		if (run_end - run_beg < RUN_MIN)
			continue;

		/*
		 * AND THE RUN HAS TO BE DELIMITED, which is what replaces the
		 * walk to the C string's NUL.
		 *
		 * The boundary mattered for one reason: a run must not be a
		 * window onto bytes that belong to something else - a symbol
		 * table, a pointer, the tail of another string. Asking what is
		 * immediately BEFORE the run answers that for a fraction of
		 * the cost. A payload is an argument, so it follows a NUL, a
		 * space, a quote or an opening bracket; a run that follows
		 * anything else is a run that was cut out of the middle of
		 * something, and this module has no business in it.
		 */
		before = run_beg ? kof_u8(run_beg - 1u) : 0;
		if (before != 0 && before != ' ' && before != '\t' &&
		    before != '"' && before != '\'' && before != '(' &&
		    before != '=' && before != '\n')
			continue;

		/*
		 * WHAT THE CHILD IS, DECLARED BEFORE IT EXISTS.
		 *
		 * A name and a kind belong to a child at its START - the host
		 * spends them when the child is pushed, which is the first
		 * emit - so both have to be said before a byte is handed over.
		 * That is why the head is decoded twice: four bytes, to answer
		 * one question, and then the real pass runs from the top.
		 *
		 * THE NAME IS THE ANCHOR ITSELF, which is the whole of the
		 * provenance worth carrying: this child is what `base64 -d`
		 * was about to be handed. A reader looking at a row of decoded
		 * bytes needs to know that they are decoded and by what, and
		 * the tree row is where they look. The host composes it with
		 * the kind, so the row reads "SCRIPT base64 -d".
		 *
		 * THE KIND AND THE FORMAT ARE CLAIMED ONLY FOR TEXT. A payload
		 * that is an ELF gets neither from here - identify will say
		 * what it is, and calling it a script because of how it arrived
		 * would be this module overruling the parser about something
		 * the parser can actually see.
		 *
		 * FOR TEXT THE FORMAT HAS TO BE SAID, because nothing else can
		 * say it. KOF_FMT_SCRIPT has no sniffer and no parser - it is
		 * reached only by being DECLARED, and scan.c says why that
		 * matters: ctx->format is what kof_module_precond tests first,
		 * so a child left at zero is offered only to the modules that
		 * target unknown. A container that knew it had handed over a
		 * script would otherwise get the rules for a bare blob, and a
		 * rule written on the decoded command would be pinned to
		 * "unidentified bytes" rather than to scripts.
		 */
		{
			uint8_t  head[4];
			uint32_t hn = 0, hacc = 0, hhave = 0;
			int      text = 1;

			for (i = run_beg; i < run_end && hn < 4u; i++) {
				uint8_t c = kof_u8(i);
				int v;

				if (c == '\n' || c == '\r' || c == '=')
					continue;
				if (c >= 'A' && c <= 'Z')      v = c - 'A';
				else if (c >= 'a' && c <= 'z') v = c - 'a' + 26;
				else if (c >= '0' && c <= '9') v = c - '0' + 52;
				else if (c == '+')             v = 62;
				else if (c == '/')             v = 63;
				else                           break;
				hacc = (hacc << 6) | (uint32_t)v;
				hhave += 6u;
				if (hhave >= 8u) {
					hhave -= 8u;
					head[hn++] = (uint8_t)(hacc >> hhave);
				}
			}
			for (i = 0; i < hn; i++)
				if ((head[i] < 0x20u && head[i] != '\t' &&
				     head[i] != '\n' && head[i] != '\r') ||
				    head[i] > 0x7eu)
					text = 0;
			if (hn < 2u)
				continue;       /* decoded to nothing usable */

			/* The spelling that was matched, so the row names the
			 * decoder the file actually wrote. */
			kof_name_next(pos, which == 1 ? 15u : 9u);
			if (text) {
				kof_child_kind(KOF_ENT_SCRIPT);
				kof_child_format(KOF_FMT_SCRIPT);
			}
		}

		/*
		 * DECODE. Nothing here can be outside the alphabet except the
		 * whitespace and padding the walk deliberately kept, which are
		 * skipped rather than treated as terminators.
		 */
		for (i = run_beg; i < run_end; i++) {
			uint8_t c = kof_u8(i);
			int v;

			if (c == '\n' || c == '\r' || c == '=')
				continue;
			if (c >= 'A' && c <= 'Z')      v = c - 'A';
			else if (c >= 'a' && c <= 'z') v = c - 'a' + 26;
			else if (c >= '0' && c <= '9') v = c - '0' + 52;
			else if (c == '+')             v = 62;
			else if (c == '/')             v = 63;
			else                           break;

			acc = (acc << 6) | (uint32_t)v;
			have += 6u;
			if (have >= 8u) {
				have -= 8u;
				out[n_out++] = (uint8_t)(acc >> have);
				if (n_out == OUT_CHUNK) {
					if (!kof_emit(out, n_out))
						return;
					n_out = 0;
				}
			}
		}
		if (n_out && !kof_emit(out, n_out))
			return;
		/*
		 * A run that decoded to nothing yields no child. kof_child on
		 * an empty object would put a row in the tree that says a
		 * payload was recovered when none was.
		 */
		if (!kof_child())
			return;
		made++;
	}
}
