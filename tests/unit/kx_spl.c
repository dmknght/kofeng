/*
 * kx_spl - the defects the examiner split (phase A) recorded, held as KM_CHECK rows (green while they are there, red the day one is fixed).
 * They are properties of the SOURCE (no behaviour shows them), so each row reads the file and counts: this is the one test of the suite that
 * reads the kofexamine sources, relative to the repository root where `make unit` runs it.
 *   SPL-1  (fixed with the dashboard click rewrite; now a plain check) kv_click.c click_dialog_text held `int a = c, b = c;` that nothing read
 *   SPL-2  kofexaminer_private.h includes kofinspect.h twice (and carries a stale comment; kv_panel.h opens with an orphan comment: not held) / kv_panel.h opens with an orphan comment
 *   SPL-3  kofeditor.c (a prototype) holds functions that are not the draft: obj_sha256, obj_emu_why, say_err, say_note
 *   SPL-4  writable global state of the examiner: the kex_g_* and kex_C_* variables declared extern in kofexaminer_private.h (rule: no writable global state)
 * A row that cannot read its file FAILS (a moved file is not a fixed defect).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "known_miss.h"

static int fails;

static char *slurp(const char *path)
{
	FILE *f = fopen(path, "rb");
	long n;
	char *p;

	if (!f)
		return NULL;
	fseek(f, 0, SEEK_END);
	n = ftell(f);
	fseek(f, 0, SEEK_SET);
	p = malloc((size_t)n + 1u);
	if (p && fread(p, 1, (size_t)n, f) != (size_t)n) {
		free(p);
		p = NULL;
	}
	if (p)
		p[n] = 0;
	fclose(f);
	return p;
}

static unsigned count(const char *hay, const char *needle)
{
	unsigned n = 0;
	const char *p = hay;

	while ((p = strstr(p, needle))) {
		n++;
		p += strlen(needle);
	}
	return n;
}

int main(void)
{
	char *click = slurp("kofexamine/kv_click.c"), *ed = slurp("kofexamine/kofeditor.c"),
	     *priv = slurp("kofexamine/kofexaminer_private.h");
	unsigned i, w = 0;
	static const char *const fn[] = { "\nvoid obj_sha256(", "\nuint8_t obj_emu_why(", "\nvoid say_err(", "\nvoid say_note(" };
	const char *p;

	if (!click || !ed || !priv) {
		printf("  FAIL a source file could not be read (is the working directory the repository root?)\n");
		return 1;
	}
	/* SPL-1 is fixed: the dashboard click was rewritten (click_pick) and the dead `int a = c, b = c;` went with it. */
	if (count(click, "int a = c, b = c;") != 0) {
		printf("  FAIL kv_click.c holds a dead `int a = c, b = c;` again (SPL-1)\n");
		fails++;
	}
	KM_CHECK(count(priv, "#include \"kofinspect.h\"") <= 1, "kofexaminer_private.h includes kofinspect.h more than once", "SPL-2");
	for (i = 0; i < 4; i++)
		w += count(ed, fn[i]);
	KM_CHECK(w == 0, "kofeditor.c (a prototype) defines obj_sha256, obj_emu_why, say_err, say_note: not the draft", "SPL-3");
	/* the globals: every `extern` of a kex_g_ / kex_C_ name that is not a const object of constants */
	w = 0;
	for (p = priv; (p = strstr(p, "\nextern ")); p += 8) {
		const char *eol = strchr(p + 1, '\n');
		char line[256];
		size_t l = eol ? (size_t)(eol - p - 1) : strlen(p + 1);

		if (l >= sizeof line)
			l = sizeof line - 1u;
		memcpy(line, p + 1, l);
		line[l] = 0;
		if (strstr(line, "kex_g_") || strstr(line, "kex_C_"))
			w++;
	}
	printf("  info: SPL-4 %u kex_g_/kex_C_ globals declared\n", w);
	KM_CHECK(w == 0, "the examiner keeps writable global state (kex_g_*, kex_C_*)", "SPL-4");
	free(click); free(ed); free(priv);
	printf("kx_spl: %s\n", fails || km_failed() ? "FAILED" : "ok");
	return fails != 0 || km_failed();
}
