/*
 * kv_view_decoder.inc - THE DECODER DIALOG.
 *
 * A fragment of the BODY of `struct view` (kv_view.h includes it between the braces). It is text, not a header: it has no guard, no
 * includes and is not compiled alone. Members keep their names; moving a member between fragments moves its offset.
 * Owner after the P1 split: package P8. Main users (Inference, by unit names): kv_dialogs.c.
 * Units that name these members most (name match, approximate, 2026-11-03 count at the split): kv_dialogs.c, kv_keys.c, kv_chooser.c, kv_screen.c, kofexaminer_elfpe.c.
 * Source lines of the old kv_view.h: 858-903.
 */
	/*
	 * THE DECODER, AND IT IS A FORM RATHER THAN A REPORT.
	 *
	 * Text in, a coding chosen, a key when the coding takes one, plaintext
	 * out - the shape of every decoder tab an analyst already knows.
	 *
	 * A FORM AND NOT AN AUTOMATIC TABLE, and the reason is where the text
	 * comes from: usually NOT this file. It is pasted - out of a log, a
	 * pcap, a mail, a screenshot somebody typed back in - and a box that
	 * could only work on bytes already in the object would be closed again
	 * immediately. "Decode selection" fills the field from the hex pane,
	 * which is the convenience; typing or pasting is the normal case.
	 */
	int         enc_open;
	char        enc_in[ENC_IN_MAX];        /* the encoded text */
	char        enc_key[32];               /* for codings that take one */
	uint32_t    enc_in_off, enc_key_off;   /* how far each field scrolled */
	uint32_t    enc_type;                  /* which coding */
	/*
	 * WHICH WAY - 0 decodes, 1 encodes.
	 *
	 * The box was a decoder only, which is half of what a researcher does
	 * with a coding: the pattern that goes into a signature is the ENCODED
	 * form, so "what does cmd.exe look like in hex" is asked as often as
	 * "what does this hex say". One control, because the two directions
	 * share every other field on the form.
	 */
	int         enc_way;
	uint32_t    enc_res_n;                 /* plaintext bytes, 0 for none */
	int         enc_done;                  /* Decode has been pressed */
	/* The controls, recorded where they are drawn and read where they are
	 * clicked - the arrangement every other dialog here uses. */
	int         e_in[2], e_type[2], e_key[2], e_go[2];
	/* The second button - see draw_enc. `e_go` is Decode. */
	int         e_enc[2];
	/*
	 * THE PLAINTEXT WINDOW: how far down and how far across.
	 *
	 * A decoded script is longer than any box and its lines are longer than
	 * any width, so the result is a WINDOW over it rather than a preview of
	 * it. Both offsets are the reader's, moved by the wheel and by dragging
	 * a selection past the edge, and both are clamped where the window is
	 * drawn - which is the only place that knows how much fits.
	 */
	uint32_t    enc_voff, enc_hoff;
	int         enc_txt_y, enc_txt_x, enc_txt_w, enc_txt_h;
