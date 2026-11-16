/*
 * kx_clip - kofexamine/kv_clip.c's clipboard helpers (KXA-15): paste_extern and copy_extern run whichever of wl-*, xclip, xsel is
 * installed. The source is included; the rest of the viewer is not linked (never reached). The helpers are stub scripts in a
 * directory the test puts alone on PATH, so what each helper was CALLED with is observable:
 *
 *   xclip -o -selection clipboard  (paste)  - four arguments, the table row has no NULL after them: the argv built from it
 *                                              must end with one
 *   xclip -selection clipboard     (copy)
 */
#define _GNU_SOURCE
#include "../../kofexamine/kv_clip.c"

#include <sys/stat.h>

char g_clip[8192];
size_t g_clip_n;

static int fails, checks;

#define CK(cond, what) do { checks++; if (!(cond)) { printf("  FAIL %s\n", what); fails++; } } while (0)

/*
 * copy_selection's rendered-buffer awareness (owner-reported, 2026-11-11): a text pane showing
 * kgenome_textual_pretty's output addresses it by IDENTITY (text_under's own `rendered` test,
 * kv_text.c), never through view_map - but copy_selection read the RAW object through view_map
 * unconditionally, so a rendered selection copied bytes from an unrelated offset of the raw file
 * (owner's own repro: selecting the rendered "return $o" copied back "$kf/\",@fi", a piece of the
 * same sample's OWN obfuscation strings that happened to sit at the shifted raw offset). These five
 * are the whole surface copy_selection asks beyond kv_clip.c's own copy_osc52/copy_said (already
 * linked here): stubbed so the test drives the rendered-vs-raw branch directly, with no real view
 * or object needed.
 */
static struct object g_test_ob;
static int           g_test_text_pane;
static int           g_test_rendered;
static const uint8_t *g_test_rbuf;
static uint64_t       g_test_rbuf_n;
static const uint8_t *g_test_raw;
static uint64_t       g_test_raw_n;
static uint64_t       g_test_map_shift;

struct object *cur_obj(struct view *v) { (void)v; return &g_test_ob; }
int text_pane(struct view *v) { (void)v; return g_test_text_pane; }
int txt_pretty_view(struct object *ob, const uint8_t **p, uint64_t *n)
{
	(void)ob;
	if (!g_test_rendered)
		return 0;
	*p = g_test_rbuf;
	*n = g_test_rbuf_n;
	return 1;
}
const uint8_t *view_bytes(const struct view *v, uint64_t *n) { (void)v; if (n) *n = g_test_raw_n; return g_test_raw; }
uint64_t view_map(const struct view *v, uint64_t at, uint64_t *run) { (void)v; (void)run; return at + g_test_map_shift; }

static void test_copy_selection_rendered(void)
{
	static struct view v;
	static const uint8_t rbuf[] = "ABCDEreturn $oFGHIJ";       /* "return $o" at [5..13] */
	static const uint8_t raw[]  = "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ$kf/\",@fiZZZZZZZZZZ";

	memset(&v, 0, sizeof v);
	g_test_text_pane = 1;
	g_test_rendered = 1;
	g_test_rbuf = rbuf; g_test_rbuf_n = (uint64_t)strlen((const char *)rbuf);
	g_test_raw = raw; g_test_raw_n = (uint64_t)strlen((const char *)raw);
	g_test_map_shift = 100;         /* a raw offset that, in the bug, lands on the "$kf/\",@fi" run */

	v.sel_a = 5; v.sel_b = 13;      /* "return $o", 9 bytes, inside rbuf - not a valid raw offset at all */
	g_clip_n = 0;
	copy_selection(&v, 0);
	CK(g_clip_n == 9 && !memcmp(g_clip, "return $o", 9),
	   "copy_selection, text pane rendered: copies the RENDERED bytes at the selection, not view_map's raw ones");

	/* same view, hex-pane (not text, not rendered): sel_a/sel_b are real raw offsets, view_map applies */
	g_test_text_pane = 0;
	v.sel_a = 0; v.sel_b = 3;
	g_test_map_shift = 0;
	g_clip_n = 0;
	copy_selection(&v, 0);
	CK(g_clip_n == 4 && !memcmp(g_clip, "ZZZZ", 4),
	   "copy_selection, hex pane: unchanged, still raw bytes through view_map");
}

static void put_script(const char *dir, const char *name, const char *body)
{
	char path[512];
	FILE *f;

	snprintf(path, sizeof path, "%s/%s", dir, name);
	f = fopen(path, "w");
	if (!f)
		return;
	fputs(body, f);
	fclose(f);
	chmod(path, 0755);
}

int main(void)
{
	char dir[256], out[256], cp[300];
	size_t n;
	FILE *f;

	snprintf(dir, sizeof dir, "build/kof_kxclip_XXXXXX");
	if (!mkdtemp(dir)) {
		printf("  FAIL no scratch directory\n");
		return 1;
	}
	snprintf(cp, sizeof cp, "%s/copied", dir);
	setenv("PATH", dir, 1);

	/* the other two helpers are not installed (exit 127), so the real ones on this machine are never reached */
	put_script(dir, "wl-paste", "#!/bin/sh\nexit 127\n");
	put_script(dir, "wl-copy", "#!/bin/sh\nexit 127\n");
	put_script(dir, "xsel", "#!/bin/sh\nexit 127\n");

	/* a paste helper that says how many arguments it got and which */
	put_script(dir, "xclip", "#!/bin/sh\nprintf 'ARGS:%s:%s:%s:%s:%s' \"$#\" \"$1\" \"$2\" \"$3\" \"$4\"\n");
	n = paste_extern(out, sizeof out - 1u);
	out[n] = 0;
	CK(n > 0 && !strcmp(out, "ARGS:3:-o:-selection:clipboard:"), "paste_extern runs xclip with exactly -o -selection clipboard");

	/* a copy helper that writes what it was given and its arguments */
	{
		char body[1200];

		snprintf(body, sizeof body, "#!/bin/sh\n{ printf 'ARGS:%%s:%%s:%%s:%%s:' \"$#\" \"$1\" \"$2\" \"$3\"; while IFS= read -r l || [ -n \"$l\" ]; do printf '%%s' \"$l\"; done; } > %s\n", cp);
		put_script(dir, "xclip", body);
	}
	CK(copy_extern("hello", 5) != NULL, "copy_extern finds xclip");
	f = fopen(cp, "r");
	if (f) {
		n = fread(out, 1, sizeof out - 1u, f);
		fclose(f);
		out[n] = 0;
		CK(!strcmp(out, "ARGS:2:-selection:clipboard::hello"), "copy_extern runs xclip with exactly -selection clipboard and writes the bytes to it");
	} else {
		CK(0, "copy_extern: the helper did not run");
	}

	/* no helper installed: not an error, nothing */
	put_script(dir, "xclip", "#!/bin/sh\nexit 127\n");
	CK(paste_extern(out, sizeof out) == 0, "no helper answers: an empty paste");

	test_copy_selection_rendered();

	{
		static const char *const names[] = { "xclip", "wl-paste", "wl-copy", "xsel", "copied" };
		char p[512];
		size_t k;

		for (k = 0; k < sizeof names / sizeof names[0]; k++) {
			snprintf(p, sizeof p, "%s/%s", dir, names[k]);
			unlink(p);
		}
		rmdir(dir);
	}
	printf("%d check(s), %d failed\n", checks, fails);
	return fails ? 1 : 0;
}
