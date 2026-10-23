/*
 * diag_text_ident.c - TWO NODES THAT NAME THE SAME CONSTANT PATH ARE ABOUT ONE OBJECT: the shared links of the TEXT route (the second kind of link, KGENOME_DIAG_KIND_SHARED).
 *
 * WHY. A dropper writes a file and then runs it, and says so with the same string twice: `wget -O a URL; chmod 777 a; sh a`, `[io.file]::WriteAllBytes("C:\\x.exe", $d)` then
 * `Start-Process -FilePath C:\\x.exe`, `stream.SaveToFile "c:\\x.exe"` then `shell.Run "c:\\x.exe"`. Nothing PRODUCES the second from the first - the download's result is the
 * file, the process takes its name - so the walk's value flow (the produced kind) has no link, and a diagnose that says "the downloaded file was run" cannot be written.
 * What relates the two nodes is that they are handed THE SAME OBJECT (link-has-two-kinds): a SHARED link, whose identity is the value. Measured before this file (2026-10-21,
 * the corpora of the TEXT route): the nodes of these droppers were all there and none had a link between them.
 *
 * WHAT IS A PATH HERE. Only a CONSTANT, and only what the two ends both hold: an argument the evaluator follows to one string (a literal, a variable assigned once at the top level,
 * what `"a" + "b"` joins), or a word of a command line. Not every constant is an object: a mode (`777`), an option (`-q`), a URL, a number or a word with a space in it is
 * not, and a bare name (`a`, `arm`) is one only where the language's row says the call takes a file in that place (`pathsem`: wget's `-O`, chmod's last word, the interpreter's
 * script) - so two nodes that both say `hidden` or `22` are not the same object, and `-O a` and `chmod 777 a` are. Where the row says a file comes out of a call without being
 * named (wget keeps the last piece of the URL), that is the constant.
 *
 * WHAT IT LINKS. Value numbering over the nodes in the order they were written: for each constant a node holds, the link is from the LAST node that held it, so a file that is
 * written, made executable and run is a chain, not a clique, and the four inputs a node keeps are not spent on every earlier mention. A language that does not tell upper
 * and lower case apart (batch, powershell, vbscript, .NET) compares them without. A path built by the program is a path only when the evaluator can build it: no CFG is read, so a
 * name assigned twice is not trusted (the evaluator's `strict`). What is NOT done, and said: a command that is run by its own name (`./a`, `a.exe`) makes no node, so there is
 * nothing for the file to be linked to; a path through a variable of a function (a summary); a relative path against `cd`.
 */

#include <stdlib.h>
#include <string.h>

#include "diag_text_eval_private.h"
#include "diag_text_walk.h"
#include <celllysis/nucleo.h>

/* The longest path kept: PATH_MAX (4096) - a longer one is refused by the system it would name a file on, so it is no path of a program (a payload that has a separator in it).
 * [Inference] the Windows limit of 32767 for the \\?\ form is not read; a script that names a path past 4096 is not a case measured. It was 1024 (G10). */
#define IDENT_VMAX    4096u
#define IDENT_WORDS   64u       /* the words of one command that are read: more is said (a command of a hundred files is read for its first 64) */
/* The paths one node may hold: the words it is read for (64), the target of a redirection and the name wget keeps, with room (G10: it was 16, and the 17th path of a chmod had no link).
 * What a node names beyond it is said. It bounds the cost of a call with a hundred thousand arguments, each followed to a constant. */
#define IDENT_CANDS   128u

struct ident_ent {
	uint32_t hash, off, len, last;  /* the value in the arena, and the node + 1 that held it last */
	uint8_t  made;                  /* a node that makes a file has held it: it is an object of this script's and not a name the system has (`/bin/sh`) */
};

struct kgenome_dtx_ident {
	uint32_t        *ntok;          /* by node: the token that made it, + 1 (0: none, a node of another route) */
	uint32_t         nn, cn;
	uint8_t         *arena;
	uint32_t         na, ca;
	struct ident_ent *tab;
	uint32_t         ntab, ctab;
	/* THE PASS'S JUMP TABLES (made by kgenome_dtx_ident for its length and freed with it, NULL otherwise): for each token j the first token at or after j that is a statement stop
	 * (`stop`), the first argument separator that a bracket does not hide (`comma`), and the first output redirection (`redir`); x->nt when there is none. */
	uint32_t        *stop, *comma, *redir;
};

/* ---- the node -> token map, kept while the walk makes nodes --------------------------------------------------------- */

void kgenome_dtx_ident_note(struct kgenome_dtx *x, int32_t node, uint32_t tok)
{
	struct kgenome_dtx_ident *id = x->ident;

	if (node < 0 || x->layer)
		return;
	if (!id) {
		if (!kgenome_dtx_charge(x, sizeof *id))
			return;
		id = calloc(1, sizeof *id);
		if (!id) {
			kgenome_diag_note(x->s, KGENOME_NOMEM);
			x->oom = 1;
			return;
		}
		x->ident = id;
	}
	if ((uint32_t)node >= id->cn) {
		uint32_t old = id->cn;

		if (!kgenome_dtx_grow(x, (void **)&id->ntok, &id->cn, (uint32_t)node + 1u, sizeof *id->ntok))
			return;
		memset(id->ntok + old, 0, (size_t)(id->cn - old) * sizeof *id->ntok);
	}
	id->ntok[node] = tok + 1u;
	if ((uint32_t)node >= id->nn)
		id->nn = (uint32_t)node + 1u;
}

void kgenome_dtx_ident_free(struct kgenome_dtx *x)
{
	struct kgenome_dtx_ident *id = x->ident;

	if (!id)
		return;
	free(id->ntok);
	free(id->arena);
	free(id->tab);
	free(id);
	x->ident = NULL;
}

/* ---- what a path looks like ------------------------------------------------------------------------------------------ */

/* The value has a separator, or a name and an extension that has a letter in it (`a.exe`, not `1.2.3.4` or `v1.0`). Not a URL, no space, no control byte. */
static int path_like(const uint8_t *p, uint32_t n)
{
	uint32_t i, dot = 0;
	int sep = 0;

	if (!n || n > IDENT_VMAX || p[0] == '-' || p[0] == '+')
		return 0;
	if (n >= 5u && !memcmp(p, "/dev/", 5))       /* a device (the null device a command's output is thrown into) is nobody's file */
		return 0;
	for (i = 0; i < n; i++) {
		if (p[i] <= ' ' || p[i] == 0x7f)
			return 0;
		if (p[i] == '/' || p[i] == '\\')
			sep = 1;
		else if (p[i] == '.' && i)
			dot = i;
		else if (p[i] == ':' && i + 2u < n && p[i + 1u] == '/' && p[i + 2u] == '/')
			return 0;               /* a URL is where a thing is, not a file of the machine */
		else if (p[i] == '$' || p[i] == '%' || p[i] == '`' || p[i] == '*' || p[i] == '?')
			return 0;               /* a value the shell or the program still has to expand: not this constant */
	}
	if (sep)
		return n > 1u || (p[0] != '/' && p[0] != '\\');
	if (dot && dot + 1u < n && n - dot - 1u <= 6u) {
		int letter = 0;

		for (i = dot + 1u; i < n; i++) {
			if (!kof_is_alnum((uint8_t)p[i]))
				return 0;
			letter |= kof_is_alpha(p[i]);
		}
		return letter;
	}
	return 0;
}

/* A word that is no object whatever the call: a number, a mode (`755`, `u+x`). */
static int mode_word(const uint8_t *p, uint32_t n)
{
	uint32_t i;

	for (i = 0; i < n && kof_is_digit(p[i]); i++)
		;
	if (i == n)
		return 1;
	for (i = 0; i < n && kof_byte_in_set(p[i], "ugoa"); i++)
		;
	if (i < n && kof_byte_in_set(p[i], "+-=")) {
		for (i++; i < n && kof_byte_in_set(p[i], "rwxXstugo"); i++)
			;
		return i == n;
	}
	return 0;
}

/* A plain file name: letters, digits and a few marks, no space, no expansion. The only bare word a row's table may call a path. */
static int bare_name(const uint8_t *p, uint32_t n)
{
	uint32_t i;

	if (!n || n > 255u || p[0] == '-' || p[0] == '.')
		return 0;
	for (i = 0; i < n; i++)
		if (!(kof_is_alnum((uint8_t)p[i]) || p[i] == '_' || p[i] == '-' || p[i] == '.'))
			return 0;
	return 1;
}

/* ---- the table of values --------------------------------------------------------------------------------------------- */

static uint32_t ent_hash(void *ctx, const void *slot)
{
	(void)ctx;
	return ((const struct ident_ent *)slot)->hash;
}

/* The entry of value p/n, made when there is none; NULL when memory is refused. */
static struct ident_ent *val_entry(struct kgenome_dtx *x, struct kgenome_dtx_ident *id, const uint8_t *p, uint32_t n)
{
	int fold = x->lang->fold;
	uint32_t h = kgenome_dtx_name_hash(x->seed, p, n, fold), i;

	if (!kgenome_dtx_oa_grow(x, (void **)&id->tab, &id->ctab, id->ntab, 64u, sizeof *id->tab, ent_hash))
		return NULL;
	for (i = h & (id->ctab - 1u); id->tab[i].len; i = kgenome_oatab_next(i, id->ctab), x->probes++)
		if (id->tab[i].hash == h && id->tab[i].len == n && kgenome_dtx_name_eq(id->arena + id->tab[i].off, p, n, fold))
			return &id->tab[i];
	if (id->na + n > id->ca && !kgenome_dtx_grow(x, (void **)&id->arena, &id->ca, id->na + n, 1u))
		return NULL;
	memcpy(id->arena + id->na, p, n);
	id->tab[i].hash = h;
	id->tab[i].off = id->na;
	id->tab[i].len = n;
	id->tab[i].last = 0;
	id->tab[i].made = 0;
	id->na += n;
	id->ntab++;
	return &id->tab[i];
}

/* ---- the link ------------------------------------------------------------------------------------------------------- */

/* Does the node make a file (write it, fetch into it, move into it, make a pipe there): what the script makes it may then change and run. */
static int makes_file(uint16_t cap)
{
	return cap == KGENOME_NUCLEO_WRITE || cap == KGENOME_NUCLEO_HTTP_FETCH || cap == KGENOME_NUCLEO_FILE_RENAME || cap == KGENOME_NUCLEO_PIPE;
}

/*
 * The node holds path p/n. If a node that makes the file has held it, the last node that held it is the one this shares the object with (a shared link, role PATH), and this is the
 * last holder from now on. A path no node of the script makes is a name the system has (`/bin/sh`, `/etc/passwd`): two nodes that name it are not about one object the script
 * produced, and a link there would join every reverse shell to every other.
 */
static void hold(struct kgenome_dtx *x, struct kgenome_dtx_ident *id, uint32_t node, const uint8_t *p, uint32_t n, int writes)
{
	struct ident_ent *e = val_entry(x, id, p, n);
	struct kgenome_diag_hit *h = kgenome_diag_hit_of(x->s, node);

	if (!e || !h)
		return;
	if (e->made && e->last && e->last - 1u != node)
		kgenome_diag_note_in(x->s, h, (uint16_t)(e->last - 1u), KGENOME_DIAG_ROLE_PATH, KGENOME_DIAG_KIND_SHARED);
	if (writes || makes_file(h->cap))
		e->made = 1;
	e->last = node + 1u;
}

/* ---- the row's table of what a call takes as a file ---------------------------------------------------------------------- */

/* The row of the command or call written at token `tok`: by the last piece of its path and without the extension of a program, as the table spells it (cmd_exts). */
static const struct kgenome_dtx_pathsem *pathsem_of(const struct kgenome_dtx *x, uint32_t tok)
{
	const struct kgenome_dtx_lang *l = x->lang;
	const uint8_t *p = x->in + x->t[tok].off;
	uint32_t n = x->t[tok].len, base = 0, k, e;

	if (!l->n_pathsem)
		return NULL;
	for (k = 0; k < n; k++)
		if (p[k] == '/' || p[k] == '\\')
			base = k + 1u;
	p += base;
	n -= base;
	for (e = 0; l->cmd_exts && l->cmd_exts[e]; e++) {
		size_t el = strlen(l->cmd_exts[e]);

		if (n > el && kgenome_dtx_name_eq(p + n - el, (const uint8_t *)l->cmd_exts[e], (uint32_t)el, 1)) {
			n -= (uint32_t)el;
			break;
		}
	}
	for (k = 0; k < l->n_pathsem; k++)
		if (strlen(l->pathsem[k].name) == n && kgenome_dtx_name_eq(p, (const uint8_t *)l->pathsem[k].name, n, l->fold))
			return &l->pathsem[k];
	return NULL;
}

/* Is the word p/n one of the options of a space separated list (as written, or without case where the row says so). */
static int opt_in(const char *list, const uint8_t *p, uint32_t n, int fold)
{
	const char *s = list;

	while (s && *s) {
		size_t m = strcspn(s, " ");

		if (m == n && kgenome_dtx_name_eq((const uint8_t *)s, p, n, fold))
			return 1;
		s += m;
		while (*s == ' ')
			s++;
	}
	return 0;
}

/* The last piece of a URL, without its query: the name wget gives the file. 0 when there is none. */
static uint32_t url_name(const uint8_t *p, uint32_t n, const uint8_t **out)
{
	uint32_t i, end = n, begin = 0;

	for (i = 0; i < n; i++)
		if (p[i] == '?' || p[i] == '#') {
			end = i;
			break;
		}
	for (i = 0; i + 2u < end; i++)
		if (p[i] == ':' && p[i + 1u] == '/' && p[i + 2u] == '/')
			begin = i + 3u;
	for (i = begin; i < end; i++)
		if (p[i] == '/')
			begin = i + 1u;
	if (begin >= end || memchr(p + begin, ':', end - begin))
		return 0;
	*out = p + begin;
	return end - begin;
}

/* ---- the words of a node ------------------------------------------------------------------------------------------------- */

struct word {
	uint8_t *p;             /* malloc'ed value, NULL when the word is not constant */
	uint32_t n;
	uint32_t off;           /* where it is written */
	uint8_t  opt;           /* begins like an option */
};

/* The value of the word that begins at token j and goes on while the tokens touch: a word of literal pieces (a bare word, a quoted string) and constant variables. */
static uint32_t read_word(struct kgenome_dtx *x, uint32_t j, uint32_t end, struct word *w)
{
	struct kgenome_dtx_val v = { 0 };
	uint32_t k = j;
	int ok = 1;

	do {
		const struct kgenome_dtx_tok *t = &x->t[k];

		if (t->k == 'I') {
			ok = ok && kgenome_dtx_ev_val_put(x, &v, x->in + t->off, t->len);
		} else if (t->k == 'S' || t->k == 'V') {
			struct kgenome_dtx_val pv;
			int built;

			if (kgenome_dtx_eval_range(x, k, k + 1u, &pv, &built)) {
				ok = ok && kgenome_dtx_ev_val_put(x, &v, pv.p, pv.n);
				kgenome_dtx_val_free(&pv);
			} else {
				ok = 0;
			}
		} else {
			ok = 0;
		}
		k++;
	} while (k < end && x->t[k].k != 'P' && x->t[k].k != 'T' && kgenome_dtx_touches(x, k));
	if (ok && v.n && v.n <= IDENT_VMAX) {
		w->p = v.p;
		w->n = v.n;
		w->opt = v.p[0] == '-' || v.p[0] == '+' || (kof_byte_in_set(v.p[0], x->lang->cmd_opt) && x->t[j].k == 'I' && v.n > 1u && kof_is_alpha(v.p[1]));
		v.p = NULL;
	}
	kgenome_dtx_val_free(&v);
	return k;
}

/*
 * Where the arguments of the node made at token `tok` end: the matching ")" of its bracket, or the end of the statement / segment - the first token at or after `tok + 1` that
 * ends a statement or is one of the row's segment ends. That token does not depend on `tok`, so it is found ONCE for every token (`stop`, a table the pass makes) and a node reads
 * it by index: a node walked to its end on its own was a walk to the end of the text for every node of a text that has none (S2-2: perl's "`ls $x{" repeated, 122 million blocks
 * at 32 KiB and 1.9 billion at 128 KiB).
 */
static int stop_at(const struct kgenome_dtx *x, uint32_t j)
{
	return kgenome_dtx_is_term(x, j) || (x->t[j].k == 'P' && kof_byte_in_set(x->in[x->t[j].off], x->lang->cmd_ends));
}

/* Is token `j` a "(", "[" or "{" whose partner is after it. */
static int opens(const struct kgenome_dtx *x, uint32_t j)
{
	return x->t[j].k == 'P' && (x->in[x->t[j].off] == '(' || x->in[x->t[j].off] == '[' || x->in[x->t[j].off] == '{') && x->match[j] > (int32_t)j;
}

/* An output redirection the command's own tokens have (`>` not followed by `&`): the reader of words leaves it out. */
static int redirect_at(const struct kgenome_dtx *x, uint32_t j)
{
	return kgenome_dtx_is_p(x, j, '>') && !kgenome_dtx_is_p(x, j + 1u, '&');
}

/*
 * The three tables, one allocation: stop[j], comma[j] and redir[j] are the first token at or after j that ends a statement, that separates two arguments (a "," not inside a bracket
 * opened after j: the walk goes over a bracket by its partner), and that is an output redirection - x->nt when there is none. Each is what a loop over [j, end) asked of
 * every node and answered by walking, and a text of n nodes with no stop walked n times to its end (S2-2, and the same in arg_paths and in the redirection loop of cmd_paths).
 * 0 when memory is refused (said).
 */
static int jumps_make(struct kgenome_dtx *x, struct kgenome_dtx_ident *id)
{
	uint32_t *t, j, nt = x->nt;

	if (!kgenome_dtx_charge(x, 3u * ((uint64_t)nt + 1u) * sizeof *t))
		return 0;
	t = malloc(3u * ((size_t)nt + 1u) * sizeof *t);
	if (!t) {
		kgenome_diag_note(x->s, KGENOME_NOMEM);
		x->oom = 1;
		return 0;
	}
	id->stop = t;
	id->comma = t + nt + 1u;
	id->redir = t + 2u * ((size_t)nt + 1u);
	id->stop[nt] = id->comma[nt] = id->redir[nt] = nt;
	for (j = nt; j > 0; j--) {
		uint32_t k = j - 1u;

		id->stop[k] = stop_at(x, k) ? k : id->stop[j];
		id->redir[k] = redirect_at(x, k) ? k : id->redir[j];
		if (x->t[k].k == 'P' && x->in[x->t[k].off] == ',')
			id->comma[k] = k;
		else if (opens(x, k))
			id->comma[k] = (uint32_t)x->match[k] + 1u <= nt ? id->comma[(uint32_t)x->match[k] + 1u] : nt;
		else
			id->comma[k] = id->comma[j];
	}
	return 1;
}

static void jumps_free(struct kgenome_dtx_ident *id)
{
	free(id->stop);
	id->stop = id->comma = id->redir = NULL;
}

static uint32_t args_end(const struct kgenome_dtx *x, const struct kgenome_dtx_ident *id, uint32_t tok, int *paren)
{
	uint32_t j = tok + 1u;

	*paren = kgenome_dtx_is_p(x, j, '(') && x->match[j] > 0;
	if (*paren)
		return (uint32_t)x->match[j];
	return j < x->nt ? id->stop[j] : x->nt;
}

/* Does this word begin like an option of the language. */
static int is_option(const struct kgenome_dtx *x, const uint8_t *p, uint32_t n)
{
	return n > 1u && (p[0] == '-' || p[0] == '+' || (kof_byte_in_set(p[0], x->lang->cmd_opt) && kof_is_alpha(p[1])));
}

/* The words after the command of the node made at token `tok`: a shell's or batch's, as the language's own reader reads them (so a variable that holds one is the constant it holds); powershell's, from the tokens. */
static uint32_t words_of(struct kgenome_dtx *x, uint32_t tok, uint32_t end, struct word *w)
{
	uint32_t nw = 0, j = tok + 1u;
	struct kgenome_dtx_cv *cv;

	/* the language's own reader (the variables collected once for the whole text) is built when a command holds an expansion - `$x`, `%x%`, a command substitution - and not for
	 * a command of plain words, whose tokens say what the words are: reading every dropper's variables to find that `chmod 777 a` names `a` was a third of the route's time on shell */
	if (x->lang->cmd_vals && !x->cv_tried && end > tok && memchr(x->in + x->t[tok].off, '$', x->t[end - 1u].off + x->t[end - 1u].len - x->t[tok].off) == NULL &&
	    memchr(x->in + x->t[tok].off, '%', x->t[end - 1u].off + x->t[end - 1u].len - x->t[tok].off) == NULL &&
	    memchr(x->in + x->t[tok].off, '`', x->t[end - 1u].off + x->t[end - 1u].len - x->t[tok].off) == NULL)
		goto tokens;
	cv = x->lang->cmd_vals ? kgenome_dtx_cv_get(x) : NULL;
	if (cv) {
		struct kgenome_dtx_val v[IDENT_WORDS + 2u];
		uint32_t at[IDENT_WORDS + 2u], k, n = kgenome_dtx_cv_command(cv, x->t[tok].off, v, at, IDENT_WORDS + 2u);

		for (k = 1; k < n; k++) {
			if (nw == IDENT_WORDS) {                        /* the 65th word: the command is longer than what is read, and says so */
				kgenome_dtx_cut(x);
				kgenome_dtx_val_free(&v[k]);
				continue;
			}
			if (v[k].p && v[k].n && v[k].n <= IDENT_VMAX) {
				w[nw].p = v[k].p;
				w[nw].n = v[k].n;
				w[nw].off = at[k];
				w[nw].opt = (uint8_t)is_option(x, v[k].p, v[k].n);
			} else {
				kgenome_dtx_val_free(&v[k]);
			}
			nw++;
		}
		kgenome_dtx_val_free(&v[0]);
		return nw;
	}
tokens:
	while (j < end && nw < IDENT_WORDS) {
		if (kgenome_dtx_is_p(x, j, '>') || kgenome_dtx_is_p(x, j, '<')) {
			/* a redirection is no argument (the reader of words leaves it out): its operator, its target, and the descriptor in front of it (`2>/dev/null`) */
			struct word skip;

			if (nw && w[nw - 1u].n == 1u && w[nw - 1u].p && kof_is_digit(w[nw - 1u].p[0]) && w[nw - 1u].off + 1u == x->t[j].off) {
				free(w[nw - 1u].p);
				memset(&w[--nw], 0, sizeof w[0]);
			}
			while (j < end && (kgenome_dtx_is_p(x, j, '>') || kgenome_dtx_is_p(x, j, '<') || kgenome_dtx_is_p(x, j, '&')))
				j++;
			memset(&skip, 0, sizeof skip);
			if (j < end && x->t[j].k != 'P' && x->t[j].k != 'T')
				j = read_word(x, j, end, &skip);
			free(skip.p);
			continue;
		}
		if (x->t[j].k == 'P' || x->t[j].k == 'T') {
			j++;
			continue;
		}
		w[nw].off = x->t[j].off;
		j = read_word(x, j, end, &w[nw]);
		nw++;
	}
	for (; j < end; j++)                    /* words left past the 64 read: said */
		if (x->t[j].k != 'P' && x->t[j].k != 'T') {
			kgenome_dtx_cut(x);
			break;
		}
	return nw;
}

/* Is the word written at `off` the target of an output redirection (`> f`, `>> f`): the command makes the file. `>&` and the descriptor forms are not. */
static int redirected(const struct kgenome_dtx *x, uint32_t off)
{
	while (off && (x->in[off - 1u] == ' ' || x->in[off - 1u] == '\t'))
		off--;
	return off && x->in[off - 1u] == '>' && !(off > 1u && x->in[off - 2u] == '&');
}

/* The paths a command line's node holds, by the row's table. */
static void cmd_paths(struct kgenome_dtx *x, struct kgenome_dtx_ident *id, uint32_t node, uint32_t tok, uint32_t end)
{
	const struct kgenome_dtx_lang *l = x->lang;
	const struct kgenome_dtx_pathsem *ps = pathsem_of(x, tok);
	struct word w[IDENT_WORDS + 1u];
	uint32_t nw, k, last_pos = 0, first_pos = 0, held = 0, saw_opt = 0;
	int implicit_ok = 1, text_mode = 0;

	memset(w, 0, sizeof w);
	nw = words_of(x, tok, end, w);
	for (k = 0; k < nw; k++) {
		const uint8_t *p = w[k].p;
		uint32_t n = w[k].n;
		int path = 0;

		if (!p)
			continue;
		if (w[k].opt) {
			if (ps && ps->text_opt && opt_in(ps->text_opt, p, n, l->fold))
				text_mode = 1;
			if (ps && opt_in(ps->opts, p, n, l->fold)) {
				saw_opt = 1;
				if (k + 1u < nw && w[k + 1u].p && !w[k + 1u].opt) {
					k++;
					p = w[k].p;
					n = w[k].n;
					path = 1;
				} else {
					continue;
				}
			} else if (ps && n > 2u && p[0] == '-' && p[1] != '-') {
				/* `-Ofile`: a short option with its value glued to it */
				char o[3] = { (char)p[0], (char)p[1], 0 };

				if (opt_in(ps->opts, (const uint8_t *)o, 2u, l->fold)) {
					saw_opt = 1;
					p += 2;
					n -= 2u;
					path = 1;
				} else {
					continue;
				}
			} else {
				if (ps && ps->implicit_opt && opt_in(ps->implicit_opt, p, n, l->fold))
					saw_opt |= 2u;
				continue;
			}
		} else {
			/* the positions the row says are files: the first word (an interpreter's script), the last (chmod's file) */
			if (!first_pos)
				first_pos = k + 1u;
			last_pos = k + 1u;
			if (mode_word(p, n))
				continue;
		}
		if ((path && n <= IDENT_VMAX && !mode_word(p, n)) || path_like(p, n)) {
			if (held >= IDENT_CANDS) {
				kgenome_dtx_cut(x);                    /* a node that names more paths than it holds: the rest are not linked, and it is said */
				break;
			}
			hold(x, id, node, p, n, redirected(x, w[k].off));
			held++;
		}
	}
	if (ps && ps->pos && !text_mode) {
		uint32_t at = ps->pos == 1u ? first_pos : last_pos;

		if (at && w[at - 1u].p && !path_like(w[at - 1u].p, w[at - 1u].n) && !mode_word(w[at - 1u].p, w[at - 1u].n) && !w[at - 1u].opt &&
		    bare_name(w[at - 1u].p, w[at - 1u].n)) {
			if (held >= IDENT_CANDS) {
				kgenome_dtx_cut(x);
			} else {
				hold(x, id, node, w[at - 1u].p, w[at - 1u].n, 0);        /* a bare name in the place the row says is a file */
				held++;
			}
		}
	}
	/* the target of an output redirection is a file the command makes: `base64 -d > /tmp/x.sh` (the reader of words leaves a redirection out, the tokens have it) */
	for (k = id->redir[tok + 1u]; k + 1u < end; k = id->redir[k + 1u]) {
		struct word rw;
		uint32_t at = k + 1u;

		if (kgenome_dtx_is_p(x, at, '>'))
			at++;
		memset(&rw, 0, sizeof rw);
		if (at < end && (x->t[at].k == 'I' || x->t[at].k == 'S'))
			(void)read_word(x, at, end, &rw);
		if (rw.p && (path_like(rw.p, rw.n) || bare_name(rw.p, rw.n)) && !(rw.n >= 5u && !memcmp(rw.p, "/dev/", 5))) {
			if (held >= IDENT_CANDS) {
				kgenome_dtx_cut(x);
				free(rw.p);
				break;
			}
			hold(x, id, node, rw.p, rw.n, 1);
			held++;
		}
		free(rw.p);
	}
	if (ps && ps->implicit && !(saw_opt & 1u) && (!ps->implicit_opt || (saw_opt & 2u)) && held < IDENT_CANDS) {
		for (k = 0; k < nw && implicit_ok; k++) {
			const uint8_t *nm;
			uint32_t m;

			if (w[k].p && !w[k].opt && (m = url_name(w[k].p, w[k].n, &nm)) != 0) {
				hold(x, id, node, nm, m, 0);                       /* wget keeps the last piece of the URL as the file's name */
				implicit_ok = 0;
			}
		}
	}
	for (k = 0; k < nw; k++)
		free(w[k].p);
}

/* The paths a call with a bracket, or a statement call of a language with expressions, holds: its arguments, each followed to a constant. */
static void arg_paths(struct kgenome_dtx *x, struct kgenome_dtx_ident *id, uint32_t node, uint32_t tok, uint32_t end, int paren)
{
	uint32_t from = paren ? tok + 2u : tok + 1u, j, held = 0;

	if (from >= end)
		return;
	for (;;) {
		uint32_t re = from;
		struct kgenome_dtx_val v;
		int built;

		j = id->comma[from];                    /* the first "," a bracket does not hide, by the jump table: the loop over the tokens to it was a walk to the end for every node */
		re = j < end ? j : end;
		if (re > from && kgenome_dtx_eval_range(x, from, re, &v, &built)) {
			if (path_like(v.p, v.n) && !mode_word(v.p, v.n)) {
				if (held >= IDENT_CANDS) {              /* the argument past the paths a node holds: said, and the rest of the arguments are not read */
					kgenome_dtx_cut(x);
					kgenome_dtx_val_free(&v);
					break;
				}
				hold(x, id, node, v.p, v.n, 0);
				held++;
			}
			kgenome_dtx_val_free(&v);
		}
		if (re >= end)
			break;
		from = re + 1u;
	}
}

/* The pass: every node the walk made, in the order it made them, and the paths it holds. */
void kgenome_dtx_ident(struct kgenome_dtx *x)
{
	struct kgenome_dtx_ident *id = x->ident;
	uint32_t n, saved_strict = x->strict;

	if (!id || id->nn < 2u || x->oom)
		return;
	if (!jumps_make(x, id))
		return;
	x->strict = 1;                  /* a path is trusted when the program says it once: no control flow is read here */
	for (n = 0; n < id->nn && !x->oom && !x->s->halt; n++) {
		uint32_t tok;
		int paren;
		uint32_t end;

		if (!id->ntok[n])
			continue;
		tok = id->ntok[n] - 1u;
		if (tok >= x->nt)
			continue;
		end = args_end(x, id, tok, &paren);
		if (x->lang->cmd && !paren)
			cmd_paths(x, id, n, tok, end);
		else
			arg_paths(x, id, n, tok, end, paren);
	}
	x->strict = (uint8_t)saved_strict;
	jumps_free(id);
}
