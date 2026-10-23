#ifndef KOFENG_TESTS_INTERP_ORACLE_H
#define KOFENG_TESTS_INTERP_ORACLE_H

/*
 * interp_oracle.h - the real interpreters as oracles: a script is passed base64 coded (no quote of the shell is in the way) to python 3, perl or bash, and all it prints
 * is the answer. An interpreter that is not on the machine is counted, and its cases are skipped by the caller. Shared by the tests of kuncoat's string ops
 * (uncoat/strfn_*.c) and of the command languages' evaluator (unit/script_cmds.c).
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

static unsigned skipped_py, skipped_pl;

/* ---- the interpreters ------------------------------------------------------------------- */

static inline int have(const char *tool)
{
	char cmd[96];

	snprintf(cmd, sizeof cmd, "%s --version >/dev/null 2>&1", tool);
	return system(cmd) == 0;
}

/* The script, base64 coded so that no quote of the shell is in the way; the interpreter decodes and runs it, and everything it prints is the answer. */
static inline char *b64(const char *p)
{
	static const char t[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	size_t n = strlen(p), i, w = 0;
	char *o = malloc(n * 4u / 3u + 8u);

	for (i = 0; i < n; i += 3u) {
		uint32_t v = (uint32_t)(uint8_t)p[i] << 16 | (i + 1u < n ? (uint32_t)(uint8_t)p[i + 1u] << 8 : 0u) | (i + 2u < n ? (uint8_t)p[i + 2u] : 0u);

		o[w++] = t[v >> 18 & 63u];
		o[w++] = t[v >> 12 & 63u];
		o[w++] = i + 1u < n ? t[v >> 6 & 63u] : '=';
		o[w++] = i + 2u < n ? t[v & 63u] : '=';
	}
	o[w] = 0;
	return o;
}

/* Runs `script` in the interpreter (1: python 3, 0: perl, 2: bash) and returns all it prints, NULL when the interpreter is not there or printed nothing. */
static inline char *run_script(int py, const char *script)
{
	char *code, *cmd, *buf;
	FILE *p;
	size_t w = 0, r;

	if (!have(py == 1 ? "python3" : py == 0 ? "perl" : "bash")) {
		(py ? &skipped_py : &skipped_pl)[0]++;
		return NULL;
	}
	code = b64(script);
	cmd = malloc(strlen(code) + 200u);
	if (py == 2)
		sprintf(cmd, "printf %%s '%s' | base64 -d | bash 2>&1", code);
	else
		sprintf(cmd, py ? "python3 -I -c \"import base64;exec(base64.b64decode('%s'))\" 2>&1" : "perl -MMIME::Base64 -e 'eval(decode_base64(\"%s\")); print STDERR $@ if $@' 2>&1", code);
	p = popen(cmd, "r");
	buf = malloc(1u << 26);
	free(code);
	free(cmd);
	if (!p || !buf) {
		free(buf);
		return NULL;
	}
	while ((r = fread(buf + w, 1, (1u << 26) - 1u - w, p)) > 0)
		w += r;
	buf[w] = 0;
	pclose(p);
	if (!w) {
		free(buf);
		return NULL;
	}
	return buf;
}

/* The next line of a text (the cursor moves past it). */
static inline char *next_line(char **at)
{
	char *s = *at, *e;

	if (!s || !*s)
		return NULL;
	e = strchr(s, '\n');
	if (e)
		*e = 0;
	*at = e ? e + 1 : s + strlen(s);
	return s;
}

#endif
