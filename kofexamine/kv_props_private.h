/*
 * kv_props_private.h - what the pieces of the properties page share.
 *
 * The page is built as rows (prop_add) and tables (prop_table) into g_prop; the units
 * units below only differ in WHAT they put there:
 *
 *   kv_props       the row and table builders, the tab geometry, prop_event, prop_build
 *   kv_props_proc  the Process page: environment, connections, descriptors, libraries
 *   kv_props_obj   the per-format rows of an object: ELF, PDF, PE, toolchain, ancestry
 *
 * Only the types the three share and the builders one of them offers another are here.
 * Not installed, not part of any surface; included by the kv_props*.c files only.
 */
#ifndef KOF_KV_PROPS_PRIVATE_H
#define KOF_KV_PROPS_PRIVATE_H

#include "kv.h"


/*
 * The two lists the record carries are flat text with a separator - the
 * environment is one space between assignments, the connection list one
 * newline between rows - so both feeders are "find the nth piece". Counting
 * and fetching are the same walk, which is why they are one function: a count
 * that disagreed with the fetch would show a row the table could not fill.
 */
struct prop_list {
	const char *text;
	/*
	 * HOW LONG THE BLOCK IS, because one of the two separators is NUL.
	 *
	 * The environment cannot be split on a space: a value may contain one,
	 * and a row split there shows one variable as two with the second
	 * unnamed. The collector therefore keeps the NULs between assignments,
	 * and a NUL-separated block is not a string - strlen names its first
	 * piece. 0 means "take strlen", which is what the connection list,
	 * separated by newlines, wants.
	 */
	uint32_t    len;
	char        sep;
	/* Wide enough for the longest cell either feeder writes: a raw net
	 * line is bounded by the collector at 256, and a value is cut to what
	 * a column can show anyway. */
	char        buf[4][256];
};

/* The three standard descriptors, by name, out of the record's arena - they
 * are written consecutively, so each is found by stepping past the one
 * before. */
struct prop_fdlist {
	const struct object *ob;
	const struct kof_proc_info *pi;
	char buf[64];
};

/*
 * WHAT THE PROCESS HAS MAPPED, one row per file.
 *
 * The tree already carries these as objects, so this is not a second walk of
 * anything - it reads the rows that are already there. It is worth a table
 * anyway: the tree interleaves them with the memory regions in address order,
 * which is the order the address space has and not an order anybody reads, and
 * the question "what did this load" wants them together.
 *
 * TOLD APART FROM THE MEMORY REGIONS BY NAME, which is the convention the walk
 * establishes: a region is MEM_<something> and a mapped file is its basename.
 * A name test rather than a flag because the name is what the rest of the
 * viewer already keys on, and a second marker would be a second thing to keep
 * in step.
 */
/*
 * The mapped files, as a table like the other three.
 *
 * KIND FIRST, THEN SIZE, THEN THE PATH. A reader scanning this column is
 * asking "what has this process got loaded" - an ELF, a locale table, a cache
 * - and the answer is the same six characters on most rows, which is what
 * makes a column worth reading down. The path is last because it is the one
 * that does not fit, and the one that therefore scrolls.
 *
 * THE WHOLE PATH AND NOT THE LEAF. Two mappings named `libc.so.6` may be the
 * system one and one out of a writable directory, which is the difference
 * between a normal process and an interesting one, and a basename cannot say
 * which. It is too wide for any column, so it is the column that moves under
 * shift and the wheel.
 */
struct prop_liblist {
	const struct view *v;
	char buf[3][320];
};


/* kv_props.c: the row builders. prop_say is the one way a page says a sentence (an empty case, a cut, a warning). */
void prop_add(const char *fmt, ...);
void prop_say(const char *attr, const char *fmt, ...);
void prop_head(const char *w);
const char *prop_proc_str(const struct object *ob, uint32_t off);

/* One column of a table a page declares: heading, natural width (0: measured from the data), alignment, colour. */
struct prop_col {
	const char *name;
	uint16_t    width;
	uint8_t     right;
	const char *attr;
};

/* kv_props_table.c: the page and the table renderer (kv_table.h) */
void prop_spec(struct kv_tab_spec *t, const struct prop_col *c, uint32_t n_col, uint32_t n_row, uint32_t n_sticky, int flex,
	       void (*cell)(void *, uint32_t, const char **), void *user);
void prop_table(struct view *v, struct kv_tab_spec *t);
void prop_table_page(struct view *v, struct kv_tab_spec *t, uint32_t fixed);
void prop_block(const struct dash_block *b);
const char *prop_tone_sgr(enum dash_tone t);

/* kv_props_tab.c: the table pages and the controls of the dashboard's strip */
void prop_page_table_build(struct view *v, struct object *ob);
void prop_symbols(struct view *v, const struct object *ob, uint8_t which);

/* kv_props_proc.c */
void prop_proc(struct view *v, const struct object *ob);

/* kv_props_obj.c */
void prop_pdf(const struct object *ob);
void prop_sink(void *user, const char *text);
void prop_object_rows(struct view *v, const struct object *ob, int full);

#endif /* KOF_KV_PROPS_PRIVATE_H */
