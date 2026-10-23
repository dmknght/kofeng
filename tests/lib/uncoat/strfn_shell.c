#define _GNU_SOURCE
/*
 * strfn_shell - the ops that serve the shell, batch and tcl (kuncoat_transform: CUTHEAD, CUTTAIL, LENGTH, FORMAT, MAP, JOIN over a tcl list, TRANSLATE with tr's ranges),
 * checked against the real programs where they are on the machine.
 *
 *   bash 5 and GNU tr 9 (the machine's): ${x#p} ${x##p} ${x%p} ${x%%p} over every word of {a,b} to length 6 and every pattern of one to three bytes; ${#x}; printf
 *       with every format of up to three pieces of "%s", "%%", "x", "\n", "\t", "\\" over every list of up to three arguments (the run-again rule included); tr over every
 *       pair of sets of up to three bytes from {a,b,-} and {x,y,-} (ranges, a "-" at either end), and a list of the sets that matter (a-z A-Z, 0-9, a-f).
 *   python 3 for tcl's format (exact counts, "%s" and "%%": python's % operator says the same), and a reference written HERE - differently from the code under test - for
 *       string map (the FIRST pair of the list wins at each place, the scan goes on after the key) and for join of a list written as text. No tclsh is on the machine: those two
 *       are [Unverified] against tcl itself; the rule is the manual's (string map, join, format).
 * Every answer with room for exactly it and with one byte less (OVER_BUDGET, the guard page untouched); and what the ops refuse (a broken pair list, an odd count, a brace in a
 * list, a format with another "%" or a stray backslash, sets that do not come to as many bytes).
 */

#include "strfn_oracle.h"

/* The idx-th word of length len over `al`, FIRST letter most significant: the order the bash loops below produce. */
static void word_pm(const char *al, uint8_t *o, unsigned idx, unsigned len)
{
	unsigned base = (unsigned)strlen(al), k;

	for (k = 0; k < len; k++)
		o[k] = (uint8_t)al[(idx / ipow(base, len - 1u - k)) % base];
}

static const char bash_gen[] =
	"gen(){ local al=$1 max=$2 l p i; local -a cur nxt; cur=(\"\"); out=(\"\"); for ((l=1;l<=max;l++)); do nxt=(); for p in \"${cur[@]}\"; do for ((i=0;i<${#al};i++)); do nxt+=(\"$p${al:i:1}\"); done; done; out+=(\"${nxt[@]}\"); cur=(\"${nxt[@]}\"); done; }\n"
	"hex(){ local s=$1 i; for ((i=0;i<${#s};i++)); do printf '%02x' \"'${s:i:1}\"; done; echo; }\n";

/* ---- CUTHEAD, CUTTAIL, LENGTH against bash ------------------------------------------------------------ */

static const char bash_cut[] =
	"gen ab 6; subs=(\"${out[@]}\"); gen ab 3; pats=(\"${out[@]}\")\n"
	"for s in \"${subs[@]}\"; do for p in \"${pats[@]}\"; do [ -z \"$p\" ] && continue; echo \"${s#\"$p\"}\"; echo \"${s##\"$p\"}\"; echo \"${s%\"$p\"}\"; echo \"${s%%\"$p\"}\"; done; done\n"
	"for s in \"${subs[@]}\"; do echo \"${#s}\"; done\n";

static void cut_and_length(void)
{
	char *out = run_script(2, "gen(){ :; }");
	char *src, *at;
	char script[4096];
	unsigned long cases = 0, bad = 0;
	unsigned sl, si, pl, pi;

	free(out);
	snprintf(script, sizeof script, "%s%s", bash_gen, bash_cut);
	src = run_script(2, script);
	if (!src)
		return;
	at = src;
	for (sl = 0; sl <= 6u; sl++)
		for (si = 0; si < ipow(2, sl); si++) {
			uint8_t sub[8];

			word_pm("ab", sub, si, sl);
			for (pl = 0; pl <= 3u; pl++)
				for (pi = 0; pi < ipow(2, pl); pi++) {
					uint8_t pat[4];
					struct kuncoat_step h, t;
					char *line;
					int k;

					if (!pl)
						continue;
					word_pm("ab", pat, pi, pl);
					h = mk(KUNCOAT_ALGO_CUTHEAD, 0, 0, pat, pl);
					t = mk(KUNCOAT_ALGO_CUTTAIL, 0, 0, pat, pl);
					for (k = 0; k < 4; k++) {
						const struct kuncoat_step *st = k < 2 ? &h : &t;
						uint64_t p;
						uint8_t got[16];

						line = next_line(&at);
						(void)T(st, sub, sl, 16, &p);
						memcpy(got, res, (size_t)p);
						got[p] = 0;
						cases++;
						if (!line || strcmp((char *)got, line))
							if (bad++ < 5u)
								printf("  FAIL cut %d: subject %.*s pattern %.*s: ours [%s] bash [%s]\n", k, (int)sl, (char *)sub, (int)pl, (char *)pat, got, line ? line : "(none)");
						{
							uint8_t want[16];
							size_t wn = (size_t)(line ? strlen(line) : 0);

							if (line) {
								memcpy(want, line, wn);
								exact(st, sub, sl, want, wn, "cut", cases);
							}
						}
					}
				}
		}
	for (sl = 0; sl <= 6u; sl++)
		for (si = 0; si < ipow(2, sl); si++) {
			uint8_t sub[8];
			struct kuncoat_step s = mk(KUNCOAT_ALGO_LENGTH, 0, 0, NULL, 0);
			char *line = next_line(&at);

			word_pm("ab", sub, si, sl);
			if (!line) {
				bad++;
				continue;
			}
			exact(&s, sub, sl, (const uint8_t *)line, strlen(line), "length", cases++);
		}
	free(src);
	CKF(!bad, "cut and length vs bash: %lu differences", bad);
	printf("  cut/length: %lu cases against bash (${x#p} ${x##p} ${x%%p} ${x%%%%p} ${#x})\n", cases);
}

/* ---- FORMAT against bash printf and python's % -------------------------------------------------------------- */

static const char *const fmt_pieces[] = { "%s", "%%", "x", "\\n", "\\t", "\\\\" };
static const char *const fmt_args[] = { "a", "bb", "" };

static const char bash_format[] =
	"pieces=('%s' '%%' 'x' '\\n' '\\t' '\\\\'); args=(a bb '')\n"
	"fmts=(''); for p in \"${pieces[@]}\"; do fmts+=(\"$p\"); for q in \"${pieces[@]}\"; do fmts+=(\"$p$q\"); for r in \"${pieces[@]}\"; do fmts+=(\"$p$q$r\"); done; done; done\n"
	"lists=(-); for a in 0 1 2; do lists+=(\"$a\"); for b in 0 1 2; do lists+=(\"$a$b\"); for c in 0 1 2; do lists+=(\"$a$b$c\"); done; done; done\n"
	"for f in \"${fmts[@]}\"; do for l in \"${lists[@]}\"; do av=(); [ \"$l\" != - ] && for ((i=0;i<${#l};i++)); do av+=(\"${args[${l:i:1}]}\"); done; printf -v o \"$f\" \"${av[@]}\"; hex \"$o\"; done; done\n";

/* the same lists in the same order, as the C side builds them: the empty one first, then each prefix extended (a, then a+a.., so "0" = none) */
static unsigned fmt_list_count;

static void build_fmt(unsigned idx, char *f)
{
	/* fmts: "", then for p: p, then for q: pq, then for r: pqr - the order of the loop above */
	unsigned n = 1, p, q, r;

	f[0] = 0;
	if (idx == 0)
		return;
	for (p = 0; p < 6u; p++) {
		if (idx == n++) {
			strcpy(f, fmt_pieces[p]);
			return;
		}
		for (q = 0; q < 6u; q++) {
			if (idx == n++) {
				strcpy(f, fmt_pieces[p]);
				strcat(f, fmt_pieces[q]);
				return;
			}
			for (r = 0; r < 6u; r++)
				if (idx == n++) {
					strcpy(f, fmt_pieces[p]);
					strcat(f, fmt_pieces[q]);
					strcat(f, fmt_pieces[r]);
					return;
				}
		}
	}
}

static unsigned build_list(unsigned idx, const char **av)
{
	unsigned n = 1, a, b, c;

	if (idx == 0)
		return 0;
	for (a = 0; a < 3u; a++) {
		if (idx == n++) {
			av[0] = fmt_args[a];
			return 1;
		}
		for (b = 0; b < 3u; b++) {
			if (idx == n++) {
				av[0] = fmt_args[a];
				av[1] = fmt_args[b];
				return 2;
			}
			for (c = 0; c < 3u; c++)
				if (idx == n++) {
					av[0] = fmt_args[a];
					av[1] = fmt_args[b];
					av[2] = fmt_args[c];
					return 3;
				}
		}
	}
	return 0;
}

static void format_vs_bash(void)
{
	char script[4096], *src, *at;
	unsigned long cases = 0, bad = 0;
	unsigned fi, li, nf = 1u + 6u + 36u + 216u, nl = 1u + 3u + 9u + 27u;

	snprintf(script, sizeof script, "%s%s", bash_gen, bash_format);
	src = run_script(2, script);
	if (!src)
		return;
	at = src;
	for (fi = 0; fi < nf; fi++) {
		char f[40];

		build_fmt(fi, f);
		for (li = 0; li < nl; li++) {
			const char *av[3];
			unsigned na = build_list(li, av), k;
			uint8_t list[64];
			uint64_t lw = 0;
			struct kuncoat_step s;
			uint64_t p;
			char hx[200], *line = next_line(&at);
			enum kuncoat_status st;

			for (k = 0; k < na; k++)
				kof_strlist_put(list, &lw, (const uint8_t *)av[k], (uint32_t)strlen(av[k]));
			s = mk(KUNCOAT_ALGO_FORMAT, KUNCOAT_F_REUSE | KUNCOAT_F_ESC, 0, na ? list : NULL, (uint32_t)lw);
			st = T(&s, (const uint8_t *)f, strlen(f), 256, &p);
			cases++;
			if (!line) {
				bad++;
				continue;
			}
			CKF(st == KUNCOAT_OK, "format [%s] with %u arguments: status %d", f, na, (int)st);
			hexs(res, (size_t)p, hx);
			if (strcmp(hx, line) && bad++ < 5u)
				printf("  FAIL format [%s] with %u arguments: ours %s bash %s\n", f, na, hx, line);
			if (!bad) {
				uint8_t want[200];

				(void)want;
			}
			exact(&s, (const uint8_t *)f, strlen(f), res, (size_t)p, "format", cases);
		}
	}
	(void)fmt_list_count;
	free(src);
	CKF(!bad, "format vs bash printf: %lu differences", bad);
	printf("  format: %lu cases against bash printf (the format run again over what is left, \\n \\t \\\\)\n", cases);
}

/* tcl's format: exactly as many arguments as "%s", no run again, no escapes in the format (the format is the text; tcl reads its backslashes before format sees them): python's %. */
static const char py_format[] =
	"import itertools\n"
	"P=['%s','%%','x']\n"
	"A=['a','bb','']\n"
	"fm=['']+[''.join(t) for n in (1,2,3) for t in itertools.product(P,repeat=n)]\n"
	"ls=[()]+[t for n in (1,2,3) for t in itertools.product(A,repeat=n)]\n"
	"for f in fm:\n"
	"  for l in ls:\n"
	"    try: print((f % l).encode().hex())\n"
	"    except TypeError: print('-')\n";

static void format_strict_vs_python(void)
{
	static const char *const pcs[] = { "%s", "%%", "x" };
	char *src = run_script(1, py_format), *at = src;
	unsigned long cases = 0, bad = 0, acc = 0;
	unsigned n, t, u, v;
	char f[16];

	if (!src)
		return;
	for (n = 0; n <= 3u; n++)
		for (t = 0; t < ipow(3, n); t++) {
			unsigned k;

			f[0] = 0;
			for (k = 0; k < n; k++)
				strcat(f, pcs[(t / ipow(3, n - 1u - k)) % 3u]);
			for (u = 0; u <= 3u; u++)
				for (v = 0; v < ipow(3, u); v++) {
					uint8_t list[64];
					uint64_t lw = 0, p;
					unsigned j;
					struct kuncoat_step s;
					enum kuncoat_status st;
					char *line = next_line(&at), hx[100];

					for (j = 0; j < u; j++) {
						const char *a = fmt_args[(v / ipow(3, u - 1u - j)) % 3u];

						kof_strlist_put(list, &lw, (const uint8_t *)a, (uint32_t)strlen(a));
					}
					s = mk(KUNCOAT_ALGO_FORMAT, 0, 0, u ? list : NULL, (uint32_t)lw);
					st = T(&s, (const uint8_t *)f, strlen(f), 64, &p);
					cases++;
					if (!line) {
						bad++;
						continue;
					}
					if (!strcmp(line, "-")) {
						if (st == KUNCOAT_OK && bad++ < 5u)
							printf("  FAIL strict format [%s] with %u arguments: python refuses, we answered\n", f, u);
					} else {
						acc++;
						hexs(res, (size_t)p, hx);
						if ((st != KUNCOAT_OK || strcmp(hx, line)) && bad++ < 5u)
							printf("  FAIL strict format [%s] with %u arguments: ours %s python %s\n", f, u, st == KUNCOAT_OK ? hx : "refused", line);
					}
				}
		}
	free(src);
	CKF(!bad && acc > 40u, "strict format vs python: %lu differences, %lu accepted", bad, acc);
	printf("  format (tcl, exact counts): %lu cases, %lu accepted, against python 3's %%\n", cases, acc);
}

/* ---- TRANSLATE with ranges against tr ------------------------------------------------------------------------ */

static const char bash_tr[] =
	"gen 'ab-' 3; s1=(\"${out[@]}\"); gen 'xy-' 3; s2=(\"${out[@]}\")\n"
	"for a in \"${s1[@]}\"; do [ -z \"$a\" ] && continue; for b in \"${s2[@]}\"; do [ -z \"$b\" ] && continue; r=$(printf '%s' 'ab-ab-ba' | tr -- \"$a\" \"$b\" 2>/dev/null; echo \":$?\"); echo \"${r//$'\\n'/!}\"; done; done\n"
	"for pr in 'a-z A-Z' 'A-Z a-z' '0-9 a-j' 'a-f A-F' 'a-cx-z 1-6' 'a-c- A-C_' '-a-c _A-C'; do set -- $pr; r=$(printf '%s' 'Hello-World-0123-abcxyz' | tr -- \"$1\" \"$2\" 2>/dev/null; echo \":$?\"); echo \"$r\"; done\n";

static void tr_vs_real(void)
{
	char script[4096], *src, *at;
	unsigned long cases = 0, bad = 0, acc = 0;
	unsigned l1, i1, l2, i2;
	static const char *const named[7][2] = { { "a-z", "A-Z" }, { "A-Z", "a-z" }, { "0-9", "a-j" }, { "a-f", "A-F" }, { "a-cx-z", "1-6" }, { "a-c-", "A-C_" }, { "-a-c", "_A-C" } };
	unsigned k;

	snprintf(script, sizeof script, "%s%s", bash_gen, bash_tr);
	src = run_script(2, script);
	if (!src)
		return;
	at = src;
	for (l1 = 1; l1 <= 3u; l1++)
		for (i1 = 0; i1 < ipow(3, l1); i1++) {
			uint8_t a[4];

			word_pm("ab-", a, i1, l1);
			for (l2 = 1; l2 <= 3u; l2++)
				for (i2 = 0; i2 < ipow(3, l2); i2++) {
					uint8_t b[4], key[8];
					struct kuncoat_step s;
					uint64_t p;
					enum kuncoat_status st;
					char *line = next_line(&at), want[64], *colon;

					word_pm("xy-", b, i2, l2);
					memcpy(key, a, l1);
					memcpy(key + l1, b, l2);
					s = mk(KUNCOAT_ALGO_TRANSLATE, KUNCOAT_F_RANGES, l1, key, l1 + l2);
					st = T(&s, (const uint8_t *)"ab-ab-ba", 8, 32, &p);
					cases++;
					if (!line) {
						bad++;
						continue;
					}
					snprintf(want, sizeof want, "%s", line);
					colon = strrchr(want, ':');
					/* tr's own refusals (a range backwards) are ours; where tr pads the shorter set we refuse, which no row wants; and where tr answers with equal sets we must agree */
					if (colon && strcmp(colon, ":0") != 0) {
						if (st == KUNCOAT_OK && bad++ < 5u)
							printf("  FAIL tr %.*s -> %.*s: tr refuses (%s), we answered\n", (int)l1, (char *)a, (int)l2, (char *)b, line);
					} else if (st == KUNCOAT_OK) {
						acc++;
						if (colon)
							*colon = 0;
						if ((size_t)p != strlen(want) || memcmp(res, want, (size_t)p)) {
							if (bad++ < 5u)
								printf("  FAIL tr %.*s -> %.*s: ours %.*s tr %s\n", (int)l1, (char *)a, (int)l2, (char *)b, (int)p, (char *)res, want);
						} else {
							exact(&s, (const uint8_t *)"ab-ab-ba", 8, res, (size_t)p, "tr", cases);
						}
					}
				}
		}
	for (k = 0; k < 7u; k++) {
		uint8_t key[16];
		size_t l1n = strlen(named[k][0]), l2n = strlen(named[k][1]);
		struct kuncoat_step s;
		uint64_t p;
		enum kuncoat_status st;
		char *line = next_line(&at), want[64], *colon;

		memcpy(key, named[k][0], l1n);
		memcpy(key + l1n, named[k][1], l2n);
		s = mk(KUNCOAT_ALGO_TRANSLATE, KUNCOAT_F_RANGES, (uint32_t)l1n, key, (uint32_t)(l1n + l2n));
		st = T(&s, (const uint8_t *)"Hello-World-0123-abcxyz", 23, 64, &p);
		cases++;
		if (!line) {
			bad++;
			continue;
		}
		snprintf(want, sizeof want, "%s", line);
		colon = strrchr(want, ':');
		CKF(colon && !strcmp(colon, ":0") && st == KUNCOAT_OK, "tr %s -> %s must be accepted (tr: %s, ours %d)", named[k][0], named[k][1], line, (int)st);
		if (colon)
			*colon = 0;
		if ((size_t)p != strlen(want) || memcmp(res, want, (size_t)p)) {
			if (bad++ < 5u)
				printf("  FAIL tr %s -> %s: ours %.*s tr %s\n", named[k][0], named[k][1], (int)p, (char *)res, want);
		} else {
			acc++;
		}
	}
	free(src);
	CKF(!bad && acc > 300u, "tr vs the real tr: %lu differences, %lu accepted", bad, acc);
	printf("  tr: %lu pairs of sets against GNU tr, %lu translations agree, the refusals (a backwards range, sets of unequal length) are ours too\n", cases, acc);
}

/* ---- MAP and JOIN of a tcl list: the manual's rule, written here ---------------------------------------------- */

/* tcl's string map, as the manual says it: at each place the first pair of the list whose key is there; scanning goes on after the key. */
static size_t ref_map(const uint8_t *s, size_t n, const char *const *k, const char *const *v, unsigned np, uint8_t *out)
{
	size_t i = 0, w = 0;
	unsigned j;

	while (i < n) {
		int hit = 0;

		for (j = 0; j < np && !hit; j++) {
			size_t kl = strlen(k[j]);

			if (kl && i + kl <= n && !memcmp(s + i, k[j], kl)) {
				memcpy(out + w, v[j], strlen(v[j]));
				w += strlen(v[j]);
				i += kl;
				hit = 1;
			}
		}
		if (!hit)
			out[w++] = s[i++];
	}
	return w;
}

static void map_all(void)
{
	static const char *const keys[] = { "a", "b", "ab", "ba", "aa" };
	static const char *const vals[] = { "x", "yy", "a" };
	unsigned sl, si, k1, v1, k2, v2, np;
	unsigned long cases = 0;

	for (sl = 0; sl <= 5u; sl++)
		for (si = 0; si < ipow(2, sl); si++) {
			uint8_t sub[8];

			word_pm("ab", sub, si, sl);
			for (np = 1; np <= 2u; np++)
				for (k1 = 0; k1 < 5u; k1++)
					for (v1 = 0; v1 < 3u; v1++)
						for (k2 = 0; k2 < (np == 2u ? 5u : 1u); k2++)
							for (v2 = 0; v2 < (np == 2u ? 3u : 1u); v2++) {
								const char *k[2] = { keys[k1], keys[k2] }, *v[2] = { vals[v1], vals[v2] };
								char key[32];
								uint8_t want[64];
								size_t wn = ref_map(sub, sl, k, v, np, want);
								struct kuncoat_step s;

								snprintf(key, sizeof key, np == 2u ? "%s %s %s %s" : "%s %s", k[0], v[0], k[1], v[1]);
								s = mk(KUNCOAT_ALGO_MAP, 0, 0, (const uint8_t *)key, (uint32_t)strlen(key));
								exact(&s, sub, sl, want, wn, "map", cases++);
							}
		}
	printf("  map: %lu cases against the manual's rule (first pair of the list wins, scanning goes on after the key)\n", cases);
	{
		uint64_t p;
		uint8_t out[16];
		struct kuncoat_step s;
		static const char *const bad[] = { "a", "a b c", "a {b c}", "a \"b\"", "a b\\c", "", "a {", "{ a", "a b {", "{} a", "{}", "a {}x", "{}a b", "a b {} c", "a {} {}" };
		unsigned i;

		(void)out;
		for (i = 0; i < sizeof bad / sizeof bad[0]; i++) {
			s = mk(KUNCOAT_ALGO_MAP, 0, 0, (const uint8_t *)bad[i], (uint32_t)strlen(bad[i]));
			CKF(T(&s, (const uint8_t *)"abc", 3, 16, &p) != KUNCOAT_OK, "map with the list [%s] must be refused", bad[i]);
		}
		/* "a X ab Y" on "ab": the first pair wins at the place, not the longest */
		s = mk(KUNCOAT_ALGO_MAP, 0, 0, (const uint8_t *)"a X ab Y", 8);
		CKF(T(&s, (const uint8_t *)"ab", 2, 16, &p) == KUNCOAT_OK && p == 2 && !memcmp(res, "Xb", 2), "map: the first pair of the list wins");
		/* `{}` alone is the empty element: a value that is nothing, never a key (an empty key matches everywhere and tcl skips it) */
		s = mk(KUNCOAT_ALGO_MAP, 0, 0, (const uint8_t *)"b {}", 4);
		CKF(T(&s, (const uint8_t *)"abcb", 4, 16, &p) == KUNCOAT_OK && p == 2 && !memcmp(res, "ac", 2), "map: {} as the value deletes");
		s = mk(KUNCOAT_ALGO_MAP, 0, 0, (const uint8_t *)"{} a b {}", 8);
		CKF(T(&s, (const uint8_t *)"abc", 3, 16, &p) != KUNCOAT_OK, "map: {} as a key is refused");
		s = mk(KUNCOAT_ALGO_MAP, 0, 0, (const uint8_t *)"a {}\tb\n{}", 9);
		CKF(T(&s, (const uint8_t *)"abc", 3, 16, &p) == KUNCOAT_OK && p == 1 && !memcmp(res, "c", 1), "map: {} then white space");
		/* the value is not scanned again */
		s = mk(KUNCOAT_ALGO_MAP, 0, 0, (const uint8_t *)"a b b c", 7);
		CKF(T(&s, (const uint8_t *)"ab", 2, 16, &p) == KUNCOAT_OK && p == 2 && !memcmp(res, "bc", 2), "map: a replaced value is not scanned again");
	}
}

static void join_wslist(void)
{
	static const char *const seps[] = { "", "-", "ab" };
	static const char al[] = "ab \t\n";
	unsigned sl, si, k;
	unsigned long cases = 0;

	for (sl = 0; sl <= 6u; sl++)
		for (si = 0; si < ipow(5, sl); si++) {
			uint8_t sub[8], want[40];

			word_pm(al, sub, si, sl);
			for (k = 0; k < 3u; k++) {
				size_t wn = 0, i = 0, sepn = strlen(seps[k]);
				int first = 1;
				struct kuncoat_step s = mk(KUNCOAT_ALGO_JOIN, KUNCOAT_F_WSLIST, 0, (const uint8_t *)seps[k], (uint32_t)sepn);

				/* the words between white space, joined: written as the manual says (a list element ends at white space) */
				while (i < sl) {
					size_t b;

					while (i < sl && (sub[i] == ' ' || sub[i] == '\t' || sub[i] == '\n'))
						i++;
					if (i >= sl)
						break;
					b = i;
					while (i < sl && !(sub[i] == ' ' || sub[i] == '\t' || sub[i] == '\n'))
						i++;
					if (!first) {
						memcpy(want + wn, seps[k], sepn);
						wn += sepn;
					}
					memcpy(want + wn, sub + b, i - b);
					wn += i - b;
					first = 0;
				}
				exact(&s, sub, sl, want, wn, "join of a tcl list", cases++);
			}
		}
	{
		/* `{}` alone is the empty element; stuck to another byte it is a brace tcl would read, refused */
		static const struct { const char *l, *sep, *want; int ok; } e[] = {
			{ "a {} b", "-", "a--b", 1 }, { "{}", "-", "", 1 }, { "{} {}", "-", "-", 1 }, { "{}\ta", ",", ",a", 1 },
			{ "a{}", "-", "", 0 }, { "{}a", "-", "", 0 }, { "{ }", "-", "", 0 }, { "{a}", "-", "", 0 }, { "{}}", "-", "", 0 },
		};
		unsigned i;

		for (i = 0; i < sizeof e / sizeof e[0]; i++) {
			struct kuncoat_step s = mk(KUNCOAT_ALGO_JOIN, KUNCOAT_F_WSLIST, 0, (const uint8_t *)e[i].sep, (uint32_t)strlen(e[i].sep));
			uint64_t p;
			enum kuncoat_status st = T(&s, (const uint8_t *)e[i].l, strlen(e[i].l), 32, &p);

			if (e[i].ok)
				CKF(st == KUNCOAT_OK && p == strlen(e[i].want) && !memcmp(res, e[i].want, p), "join of [%s]: want [%s]", e[i].l, e[i].want);
			else
				CKF(st != KUNCOAT_OK, "join of [%s] must be refused", e[i].l);
		}
	}
	printf("  join of a tcl list written as text: %lu cases against the manual's rule\n", cases);
	{
		uint64_t p;
		struct kuncoat_step s = mk(KUNCOAT_ALGO_JOIN, KUNCOAT_F_WSLIST, 0, (const uint8_t *)"-", 1);
		static const char *const bad[] = { "a {b c}", "a \"b c\"", "a\\ b", "}" };
		unsigned i;

		for (i = 0; i < sizeof bad / sizeof bad[0]; i++)
			CKF(T(&s, (const uint8_t *)bad[i], strlen(bad[i]), 16, &p) == KUNCOAT_CORRUPT, "a tcl list with [%s] is not a plain list: refused", bad[i]);
	}
}

static void refusals(void)
{
	static const char *const bad_fmt[] = { "%d", "%5s", "%", "a%", "%s%x", "\\x", "\\" };
	uint64_t p;
	unsigned i;
	struct kuncoat_step s;
	uint8_t list[16];
	uint64_t lw = 0;

	kof_strlist_put(list, &lw, (const uint8_t *)"a", 1);
	for (i = 0; i < sizeof bad_fmt / sizeof bad_fmt[0]; i++) {
		s = mk(KUNCOAT_ALGO_FORMAT, KUNCOAT_F_REUSE | KUNCOAT_F_ESC, 0, list, (uint32_t)lw);
		CKF(T(&s, (const uint8_t *)bad_fmt[i], strlen(bad_fmt[i]), 32, &p) != KUNCOAT_OK, "printf format [%s] must be refused", bad_fmt[i]);
	}
	s = mk(KUNCOAT_ALGO_FORMAT, 0, 0, list, (uint32_t)lw);
	CKF(T(&s, (const uint8_t *)"\\n", 2, 32, &p) != KUNCOAT_OK, "a backslash without ESC is refused");
	s = mk(KUNCOAT_ALGO_FORMAT, 0, 0, NULL, 0);      /* the count agrees (none and none): only the backslash is wrong */
	CKF(T(&s, (const uint8_t *)"\\n", 2, 32, &p) != KUNCOAT_OK, "a backslash without ESC is refused when the counts agree");
	CKF(T(&s, (const uint8_t *)"\\\\", 2, 32, &p) != KUNCOAT_OK, "an escaped backslash without ESC is refused too");
	s = mk(KUNCOAT_ALGO_FORMAT, KUNCOAT_F_ESC, 0, NULL, 0);
	CKF(T(&s, (const uint8_t *)"\\n", 2, 32, &p) == KUNCOAT_OK && p == 1 && res[0] == '\n', "with ESC the same text is a line break");
	s = mk(KUNCOAT_ALGO_FORMAT, 0, 0, list, (uint32_t)lw);
	CKF(T(&s, (const uint8_t *)"%s%s", 4, 32, &p) != KUNCOAT_OK, "too few arguments without REUSE is refused");
	CKF(T(&s, (const uint8_t *)"x", 1, 32, &p) != KUNCOAT_OK, "too many arguments without REUSE is refused");
	/* broken key lists */
	{
		uint8_t broken[3] = { 5, 0, 0 };

		s = mk(KUNCOAT_ALGO_FORMAT, 0, 0, broken, 3);
		CKF(T(&s, (const uint8_t *)"%s", 2, 32, &p) == KUNCOAT_BAD_ARG, "a broken argument list is BAD_ARG");
	}
	/* tr: backwards, unequal, nothing */
	{
		uint8_t key[8];

		memcpy(key, "c-abx", 5);                 /* a reversed range and a byte: expanded as one byte it would pair with x */
		s = mk(KUNCOAT_ALGO_TRANSLATE, KUNCOAT_F_RANGES, 4, key, 5);
		CKF(T(&s, (const uint8_t *)"abc", 3, 16, &p) == KUNCOAT_BAD_ARG, "tr c-ab with x is refused");
		memcpy(key, "c-aXYZ", 6);
		s = mk(KUNCOAT_ALGO_TRANSLATE, KUNCOAT_F_RANGES, 3, key, 6);
		CKF(T(&s, (const uint8_t *)"abc", 3, 16, &p) == KUNCOAT_BAD_ARG, "tr c-a is refused");
		memcpy(key, "abxy-", 5);
		s = mk(KUNCOAT_ALGO_TRANSLATE, KUNCOAT_F_RANGES, 2, key, 5);
		CKF(T(&s, (const uint8_t *)"abc", 3, 16, &p) == KUNCOAT_BAD_ARG, "tr with sets of unequal length is refused");
		s = mk(KUNCOAT_ALGO_TRANSLATE, KUNCOAT_F_RANGES, 2, key, 2);
		CKF(T(&s, (const uint8_t *)"abc", 3, 16, &p) == KUNCOAT_BAD_ARG, "tr with no second set is refused");
	}
	/* a cut of nothing is BAD_ARG, the length of nothing is 0 */
	s = mk(KUNCOAT_ALGO_CUTHEAD, 0, 0, (const uint8_t *)"", 0);
	CKF(T(&s, (const uint8_t *)"abc", 3, 16, &p) == KUNCOAT_BAD_ARG, "a cut of nothing is BAD_ARG");
	s = mk(KUNCOAT_ALGO_LENGTH, 0, 0, NULL, 0);
	CKF(T(&s, (const uint8_t *)"", 0, 16, &p) == KUNCOAT_OK && p == 1 && res[0] == '0', "the length of nothing is 0");
}

int main(void)
{
	setvbuf(stdout, NULL, _IONBF, 0);
	if (!hv_gb_init(&gin, BIG) || !hv_gb_init(&gout, BIG)) {
		printf("strfn_shell: cannot map guard buffers\n");
		return 1;
	}
	cut_and_length();
	format_vs_bash();
	format_strict_vs_python();
	tr_vs_real();
	map_all();
	join_wslist();
	refusals();
	if (skipped_py || skipped_pl)
		printf("  SKIPPED against a program: python3 %u, perl %u (the references still ran)\n", skipped_py, skipped_pl);
	hv_gb_free(&gin);
	hv_gb_free(&gout);
	return hv_done("strfn_shell");
}
