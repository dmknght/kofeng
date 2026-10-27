/*
 * kv_dashdata.h - WHAT THE DASHBOARD SAYS, as data.
 *
 * Every page's content is produced here by functions that RETURN it - column definitions, a row count, the text of
 * a cell, how many rows the header claimed that the parse did not keep, the result of a filter - and that know
 * nothing of a terminal: no struct out, no geometry, no escape sequence. The renderer (kv_props*.c) walks this and
 * draws it, and a test asserts on it with no viewer and no screen.
 *
 *   dash_header      the format block of the overview, as meaning: format, abi, linking, entry, size, layout, declared counts
 *   dash_regions     the engine's division of the object, the share of each, and the partition check
 *   dash_anomalies   what the parser thought was wrong
 *   dash_heuristic   the engine's heuristic result and its traces
 *   dash_layout      the segment and section tables (columns, rows, what was declared)
 *   dash_syms        the import or export rows after the filter, and why there are none when there are none
 *   dash_infect_*    the Infection dialog's first page: where a binary is commonly infected, the engine's ranges flagged
 *   dash_shell_*     its second: the data that carries execute permission, and what the shellcode finder said
 *   dash_tabs        the strip's labels
 *
 * A row of the overview carries TONES ("this is a name", "this is a place", "this is worth reading"), not colours:
 * which SGR a tone is belongs to the renderer.
 */
#ifndef KV_DASHDATA_H
#define KV_DASHDATA_H

/* The kinds of fact a cell or span can hold. The first group are the overview's; the second only name columns of a table
 * whose neighbours would otherwise share a colour (a type, a flag set, a second kind of address, a name). */
enum dash_tone { DT_NONE = 0, DT_DIM, DT_ID, DT_LOC, DT_SIZE, DT_WARN, DT_BAD, DT_HEUR,
		 DT_NAME, DT_TYPE, DT_FLAG, DT_ALT, DT_BIND,
		 DT_REFS, DT_ENT };

#define DASH_SPANS 12u
#define DASH_ROWS  96u

/* One labelled row of the overview: its label, and up to DASH_SPANS runs of text each with a tone. A span's text
 * carries its own padding, so a column of rows lines up without the renderer knowing the columns. */
struct dash_span {
	enum dash_tone tone;
	char text[72];
};

struct dash_row {
	char             label[16];
	enum dash_tone   label_tone;
	uint32_t         n;
	struct dash_span s[DASH_SPANS];
};

/* A block of rows under a heading (head[0] == 0: none). `not_shown` counts what the producer had and the bound cut:
 * a cap bounds cost and is said, never silent. */
struct dash_block {
	char            head[16];
	uint32_t        n;
	uint32_t        not_shown;
	struct dash_row row[DASH_ROWS];
};

int dash_has_header(const struct object *ob);
void dash_header(const struct object *ob, struct dash_block *b);
void dash_regions(const struct view *v, const struct object *ob, struct dash_block *b);
void dash_anomalies(const struct object *ob, struct dash_block *b);
void dash_heuristic(const struct object *ob, struct dash_block *b);

/* ---- the layout tables ---------------------------------------------------------------------------------- */

#define DASH_COLS 12u
#define DASH_CELL 40u

enum dash_lay { DASH_LAY_SEG = 0, DASH_LAY_SEC = 1 };

struct dash_table {
	uint32_t    n_col;
	const char *head[DASH_COLS];
	enum dash_tone tone[DASH_COLS];   /* what kind of fact each column holds (the renderer picks the colour) */
	uint32_t    lead;        /* how many leading columns identify the row (index, name or type) */
	uint32_t    n_row;       /* rows the parse kept and the table lists */
	uint32_t    declared;    /* what the header claimed */
	uint32_t    not_shown;   /* declared - n_row when the header claims more than was kept, else 0 */
	const char *none;        /* when n_col == 0: the sentence that says why there is no such table */
};

/* Fill `t` for one of the two tables of `ob`. n_col == 0 says there is none (see `none`). */
void dash_layout(const struct object *ob, enum dash_lay which, struct dash_table *t);
/* The text of one row, one cell per column, each NUL-terminated inside DASH_CELL. Control bytes of a name from the
 * file are made visible ('?'); a row past n_row gives empty cells. */
void dash_layout_cell(const struct object *ob, enum dash_lay which, uint32_t row, char c[][DASH_CELL]);
/* The entropy cell of one row (the last column), bits per byte with two decimals, "-" for no bytes, a trailing "+" when
 * the range is longer than the bound and only its prefix was counted. The same text is the last cell of dash_layout_cell. */
void dash_layout_entropy(const struct object *ob, enum dash_lay which, uint32_t row, char *out, size_t cap);
/* Natural width of each column (the entropy column by its heading: it is computed only for the rows drawn). */
void dash_layout_widths(const struct object *ob, enum dash_lay which, uint16_t w[DASH_COLS]);

/* ---- the symbol tables ---------------------------------------------------------------------------------- */

/* The filter, as the data layer takes it: text, folding, regex (compiled by the caller with the engine's compiler;
 * `bad` when it refused, and then nothing matches). */
struct dash_filter {
	const char    *text;
	int            icase, rx, bad;
	const uint8_t *prog;
	uint32_t       prog_n;
	const char    *err;
};

int dash_filter_ok(const struct dash_filter *f, const char *name, uint32_t n);

enum dash_why { DASH_OK = 0, DASH_NA, DASH_NONE, DASH_FILTER, DASH_RX };

#define DASH_SYM_COLS 9u

struct dash_syms {
	enum dash_why why;               /* DASH_OK, or the one reason there are no rows */
	uint32_t      n;                 /* rows listed, after the filter */
	uint32_t      got;               /* what the half holds, before it */
	int           cut;               /* the block was cut: 0, 1 no room, 2 source limit */
	int           wd, sw, nw;        /* hex digits of a value, width of size, longest name */
	const struct object *ob;
	uint32_t      idx[KOF_SYM_MAX_RECS];
};

struct dash_symcell {
	char c[8][40];
	char name[KOF_SYM_NAME_MAX + 1u];
	const char *cell[DASH_SYM_COLS];
};

extern const char *const dash_sym_head[DASH_SYM_COLS];

void dash_syms_load(const struct view *v, const struct dash_filter *f, const struct object *ob, uint8_t which,
		    struct dash_syms *S);
void dash_syms_cell(const struct dash_syms *S, uint32_t row, struct dash_symcell *out);
/* Is this row the symbol a shellcode finder named. */
int dash_syms_found(const struct dash_syms *S, uint32_t row);

/* ---- the Infection dialog ------------------------------------------------------------------------------- */

/* A cell of these two tables is at most this wide before the renderer clips it (a region's name is the longest). The value
 * column has a buffer of its own (DASH_VALUE_CELL): it is the only cell that is thousands of characters. */
#define DASH_WIDE KOFSCFIND_ROW_NAME
#define DASH_INF_COLS 6u
#define DASH_SHELL_COLS 9u
#define DASH_WIDE_COLS 9u          /* the most columns of either table */

/* The value column shows the bytes of a row's range as hex, at most this many (the library's cap of one range's analysis,
 * KGENOME_RANGE_BYTES = 8192, the finder's largest payload); a longer range ends in " ..." and the size column has the whole
 * length. "xx " is three characters a byte. */
#define DASH_VALUE_BYTES KGENOME_RANGE_BYTES
#define DASH_VALUE_CELL  (3u * DASH_VALUE_BYTES + 8u)

/* Infected data: the regions of the object an infector commonly uses (kgenome_infect_regions) with the engine's own ranges
 * (ob->infected) flagged, and the ranges no region holds as rows of their own. The library decides which regions exist and
 * which overlap; this only spells them. `why` says the one reason there are no rows.
 * Computed ONCE per object, when the dialog is first shown, and kept on the object (dash_infect_get). */
struct dash_infect {
	enum dash_why why;               /* DASH_OK, DASH_NA (not a parsed ELF or PE, nothing reported), DASH_NONE */
	uint32_t      n, total;          /* rows kept, rows there are (a cut is said) */
	kof_buf       file;              /* the object's bytes, borrowed: the value column reads them */
	struct kgenome_infect_row *row;  /* n rows, heap */
};

/* Shellcode: the rows of kofscfind_list - the finder's payload, variables in executable memory, data ranges in it, each with
 * the library's facts about it. Computed once per object and kept on it (dash_shell_get). */
struct dash_shell {
	enum dash_why why;               /* DASH_OK, DASH_NA (no executable image), DASH_NONE */
	uint32_t      n, total;
	kof_buf       file;              /* the object's bytes, borrowed: the value column reads them */
	struct kofscfind_row *row;       /* n rows, heap */
};

struct dash_widecell {
	char c[DASH_WIDE_COLS][DASH_WIDE];
	char value[DASH_VALUE_CELL];
	const char *cell[DASH_WIDE_COLS];
	int no_value;                    /* the caller sets it while it only measures: the value text is not produced */
};

/* THE ONE BUILDER OF THE VALUE TEXT, for both tables: the bytes [off, off + size) of `f` as "48 31 c0 ...", at most
 * DASH_VALUE_BYTES of them and " ..." when there are more; "-" for a range with no file bytes (no offset, past the end of
 * the object, empty). Never reads outside `f`. dash_value_len says how long that text is without writing it. */
void dash_value_text(char *out, size_t cap, kof_buf f, uint64_t off, uint64_t size);
uint32_t dash_value_len(kof_buf f, uint64_t off, uint64_t size);

/* The analysis (once): fill `*I` / `*S` from the object, freeing what they held. dash_*_get is what the page calls: the kept
 * result of the object, made by the first call; NULL when memory is short. dash_drop frees both with the object. */
void dash_infect_load(const struct object *ob, struct dash_infect *I);
void dash_shell_load(const struct object *ob, struct dash_shell *S);
struct dash_infect *dash_infect_get(struct object *ob);
struct dash_shell *dash_shell_get(struct object *ob);
void dash_drop(struct object *ob);

void dash_infect_table(const struct dash_infect *I, struct dash_table *t);
void dash_infect_cell(const struct dash_infect *I, uint32_t row, struct dash_widecell *out);
/* Does this row overlap a range the engine reported (and so is drawn as infected). */
int dash_infect_flagged(const struct dash_infect *I, uint32_t row);
/* The widest value text of any row (the column's width, without producing any text). */
uint32_t dash_infect_value_width(const struct dash_infect *I);

void dash_shell_table(const struct dash_shell *S, struct dash_table *t);
void dash_shell_cell(const struct dash_shell *S, uint32_t row, struct dash_widecell *out);
/* Did the finder flag this row, or is the evidence strong (kofscfind_row.flagged). */
int dash_shell_flagged(const struct dash_shell *S, uint32_t row);
uint32_t dash_shell_value_width(const struct dash_shell *S);

/* ---- the strip -------------------------------------------------------------------------------------------- */

#define DASH_TABS 5u
/* The strip's labels for the book the dialog shows (view.prop_inf); returns how many. */
uint32_t dash_tabs(const struct view *v, const struct object *ob, char lab[][32]);
/* The dialog's count text: "a-b of N <unit>" ("lines" on the overview, "items" on a table page; NULL: no unit). */
void dash_count_text(char *out, size_t cap, const char *unit, uint32_t first, uint32_t shown, uint32_t total);

/* A size as "127723 bytes (124.7 KiB)" - one spelling for every row that prints one. */
void dash_size_text(char *out, size_t cap, uint64_t n);

#endif /* KV_DASHDATA_H */
