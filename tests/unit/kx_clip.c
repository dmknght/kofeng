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
