#define _GNU_SOURCE
/*
 * strfn_lists - the string ops that serve the methods and operators of every language (kuncoat_transform: REPEAT, SPLIT, JOIN, TRIM with a set, REPLACE with FIRST and
 * ICASE), attacked rather than sampled and checked against the real interpreters.
 *
 * WHAT IS CHECKED AGAINST WHAT.
 *   - python 3 and perl, where they are on the machine (one that is not there is SAID, and its cases are skipped, visibly): every answer is compared with the interpreter's own
 *     over EVERY input of a small alphabet - all strings over {a,b}, {a,A} and {a,b,A} to length 6 or 7 against every separator of one to three bytes and every replacement of
 *     nothing to two. python: str.split, re.split and re.sub with re.IGNORECASE, str.join, str * n, str.replace(.., 1), str.strip(chars); perl: split with a quoted separator, x.
 *   - a reference written HERE and written differently from the code under test (the separators are found first and the pieces cut from the list of positions, the answer of a
 *     replace is built from the matches), so that a machine without the interpreters still checks every case.
 *   - the edge of the room: every answer with room for exactly it, and with room for one byte less (OVER_BUDGET, the guard page after the output untouched).
 *   - a list that is not one (every cut of a good one, a length that runs past the buffer) is CORRUPT.
 *
 * What the interpreters say that the ops do not: split of an empty subject is one empty piece in python (the op's) and nothing in perl, which is also what DROPTRAIL gives; the perl
 * comparison therefore asks the empty subject of python's answer only.
 */

#include "strfn_oracle.h"

/* ---- SPLIT ------------------------------------------------------------------------------- */

/* The reference: the separators are found first (left to right, none overlapping, the next search beginning past a match), and the pieces are cut between the positions. */
static size_t ref_split(const uint8_t *s, size_t n, const uint8_t *sep, size_t sn, int icase, int droptrail, uint8_t *out)
{
	size_t cuts[64], nc = 0, i, k, w = 0, pieces;

	for (i = 0; i + sn <= n;) {
		int hit = 1;

		for (k = 0; k < sn && hit; k++) {
			uint8_t a = s[i + k], b = sep[k];

			if (icase) {
				a = (uint8_t)(a >= 'A' && a <= 'Z' ? a + 32 : a);
				b = (uint8_t)(b >= 'A' && b <= 'Z' ? b + 32 : b);
			}
			hit = a == b;
		}
		if (hit) {
			cuts[nc++] = i;
			i += sn;
		} else {
			i++;
		}
	}
	pieces = nc + 1u;
	while (droptrail && pieces) {
		size_t pf = pieces > 1u ? cuts[pieces - 2u] + sn : 0u, pt = pieces - 1u < nc ? cuts[pieces - 1u] : n;

		if (pt != pf)
			break;
		pieces--;
	}
	for (k = 0; k < pieces; k++) {
		size_t pf = k ? cuts[k - 1u] + sn : 0u, pt = k < nc ? cuts[k] : n, l = pt - pf;

		out[w] = (uint8_t)l;
		out[w + 1u] = (uint8_t)(l >> 8);
		out[w + 2u] = 0;
		out[w + 3u] = 0;
		memcpy(out + w + 4u, s + pf, l);
		w += 4u + l;
	}
	return w;
}

static const char *const split_als[] = { "ab", "aA", "abA" };

/* Walks every case in the order the scripts print them: fl bit 0 ignore case, bit 1 drop the empty pieces at the end. `fn` gets the case and its answer from the reference. */
static void each_split(void (*fn)(const struct kuncoat_step *s, const uint8_t *sub, unsigned sl, const uint8_t *sep, unsigned sel, const uint8_t *want, size_t wn, unsigned fl,
				   unsigned a, void *user), void *user)
{
	unsigned a, sl, si, sel, sei, fl;
	uint8_t sub[16], sep[4], want[512];

	for (a = 0; a < 3u; a++) {
		unsigned base = (unsigned)strlen(split_als[a]);

		for (fl = 0; fl < 4u; fl++) {
			if ((fl & 1u) && a == 0)        /* ignore case needs the two cases of one letter */
				continue;
			for (sl = 0; sl <= 7u; sl++)
				for (si = 0; si < ipow(base, sl); si++) {
					word(split_als[a], sub, si, sl);
					for (sel = 1; sel <= 3u; sel++)
						for (sei = 0; sei < ipow(base, sel); sei++) {
							uint32_t flags = ((fl & 1u) ? KUNCOAT_F_ICASE : 0u) | ((fl & 2u) ? KUNCOAT_F_DROPTRAIL : 0u);
							struct kuncoat_step s;

							word(split_als[a], sep, sei, sel);
							s = mk(KUNCOAT_ALGO_SPLIT, flags, 0, sep, sel);
							fn(&s, sub, sl, sep, sel, want, ref_split(sub, sl, sep, sel, (fl & 1u) != 0, (fl & 2u) != 0, want), fl, a, user);
						}
				}
		}
	}
}

static unsigned long split_cases;

static void split_ref_case(const struct kuncoat_step *s, const uint8_t *sub, unsigned sl, const uint8_t *sep, unsigned sel, const uint8_t *want, size_t wn, unsigned fl,
			   unsigned a, void *user)
{
	(void)sep; (void)sel; (void)fl; (void)a; (void)user;
	exact(s, sub, sl, want, wn, "split", split_cases++);
}

struct lines {
	char *at;
	unsigned long bad, n;
	const char *what;
	int perl;
};

static void split_line_case(const struct kuncoat_step *s, const uint8_t *sub, unsigned sl, const uint8_t *sep, unsigned sel, const uint8_t *want, size_t wn, unsigned fl,
			    unsigned a, void *user)
{
	struct lines *l = user;
	char *line = next_line(&l->at), got[1024];
	uint64_t p;

	(void)want; (void)wn;
	if (!line) {
		l->bad++;
		return;
	}
	(void)T(s, sub, sl, 1024, &p);
	list_text(res, (size_t)p, got);
	l->n++;
	if (strcmp(got, line) && l->bad++ < 5u)
		printf("  FAIL split vs %s: alphabet %s flags %u subject %.*s sep %.*s: ours %s theirs %s\n", l->what, split_als[a], fl, (int)sl, (const char *)sub, (int)sel,
		       (const char *)sep, got, line);
}

static const char py_split[] =
	"import re\n"
	"def word(al,idx,ln):\n"
	"    o=''\n"
	"    for _ in range(ln):\n"
	"        o+=al[idx%len(al)]; idx//=len(al)\n"
	"    return o\n"
	"def fmt(r): return str(len(r))+':'+','.join(x.encode().hex() for x in r)\n"
	"for al in ('ab','aA','abA'):\n"
	"  b=len(al)\n"
	"  for fl in range(4):\n"
	"    if (fl&1) and al=='ab': continue\n"
	"    for sl in range(8):\n"
	"      for si in range(b**sl):\n"
	"        s=word(al,si,sl)\n"
	"        for sel in range(1,4):\n"
	"          for sei in range(b**sel):\n"
	"            sep=word(al,sei,sel)\n"
	"            r=re.split(re.escape(sep),s,flags=re.I) if fl&1 else s.split(sep)\n"
	"            if fl&2:\n"
	"                while r and r[-1]=='': r.pop()\n"
	"            print(fmt(r))\n";

/* perl: split with a quoted separator and a limit of -1 (the end is kept) or, for DROPTRAIL, without one; an empty subject is python's answer, perl having none. */
static const char pl_split[] =
	"sub word{my($al,$idx,$ln)=@_;my $o='';for(1..$ln){$o.=substr($al,$idx%length($al),1);$idx=int($idx/length($al));}return $o;}\n"
	"sub fmt{my @r=@_;return scalar(@r).':'.join(',',map{unpack('H*',$_)}@r);}\n"
	"for my $al('ab','aA','abA'){my $b=length($al);for my $fl(0..3){next if(($fl&1)&&$al eq 'ab');for my $sl(0..7){for my $si(0..$b**$sl-1){my $s=word($al,$si,$sl);\n"
	"for my $sel(1..3){for my $sei(0..$b**$sel-1){my $sep=word($al,$sei,$sel);my @r;\n"
	"if($sl==0){@r=($fl&2)?():('');}\n"
	"elsif($fl&1){@r=split(/\\Q$sep\\E/i,$s,-1);}else{@r=split(/\\Q$sep\\E/,$s,-1);}\n"
	"if($fl&2){pop @r while(@r&&$r[-1] eq '');}\n"
	"print fmt(@r),\"\\n\";}}}}}}\n";

static void split_all(void)
{
	char *out;
	struct lines l = { 0 };

	each_split(split_ref_case, NULL);
	printf("  split: %lu cases against the reference\n", split_cases);
	out = run_script(1, py_split);
	if (out) {
		l = (struct lines){ .at = out, .what = "python" };
		each_split(split_line_case, &l);
		CKF(!l.bad, "split vs python: %lu differences in %lu cases", l.bad, l.n);
		printf("  split: %lu cases against python 3 (str.split, re.split with IGNORECASE, empty pieces at the end dropped)\n", l.n);
		free(out);
	}
	out = run_script(0, pl_split);
	if (out) {
		l = (struct lines){ .at = out, .what = "perl", .perl = 1 };
		each_split(split_line_case, &l);
		CKF(!l.bad, "split vs perl: %lu differences in %lu cases", l.bad, l.n);
		printf("  split: %lu cases against perl (split with a quoted separator)\n", l.n);
		free(out);
	}
}

/* ---- JOIN -------------------------------------------------------------------------------- */

static const char *const join_seps[] = { "", "a", "ab", "b", "bb" };
static const char *const join_pcs[] = { "", "a", "b", "ab", "ba" };

static const char py_join[] =
	"import itertools\n"
	"for n in range(0,4):\n"
	"  for pcs in itertools.product(['','a','b','ab','ba'],repeat=n):\n"
	"    for sep in ['','a','ab','b','bb']:\n"
	"      print(sep.join(pcs).encode().hex())\n";

static const char pl_join[] =
	"my @ps=('','a','b','ab','ba');my @ss=('','a','ab','b','bb');\n"
	"for my $n(0..3){my $tot=5**$n;for my $t(0..$tot-1){my @l;for my $k(0..$n-1){my $d=5**($n-1-$k);push @l,$ps[int($t/$d)%5];}\n"
	"for my $s(@ss){print unpack('H*',join($s,@l)),\"\\n\";}}}\n";

static void join_all(void)
{
	char *py = run_script(1, py_join), *pl = run_script(0, pl_join), *ap = py, *aq = pl;
	unsigned n, t, k, sidx;
	unsigned long cases = 0, bad = 0, pyn = 0, pln = 0;

	for (n = 0; n <= 3u; n++)
		for (t = 0; t < ipow(5, n); t++) {
			unsigned idx[3];
			uint8_t list[256];
			uint64_t w = 0;

			/* the last piece varies fastest, as itertools.product and the perl loop do */
			for (k = 0; k < n; k++)
				idx[k] = (t / ipow(5, n - 1u - k)) % 5u;
			for (k = 0; k < n; k++)
				kof_strlist_put(list, &w, (const uint8_t *)join_pcs[idx[k]], (uint32_t)strlen(join_pcs[idx[k]]));
			for (sidx = 0; sidx < 5u; sidx++) {
				uint8_t want[64];
				size_t wn = 0;
				struct kuncoat_step s = mk(KUNCOAT_ALGO_JOIN, 0, 0, (const uint8_t *)join_seps[sidx], (uint32_t)strlen(join_seps[sidx]));
				char hx[200], *line;

				for (k = 0; k < n; k++) {
					if (k) {
						memcpy(want + wn, join_seps[sidx], strlen(join_seps[sidx]));
						wn += strlen(join_seps[sidx]);
					}
					memcpy(want + wn, join_pcs[idx[k]], strlen(join_pcs[idx[k]]));
					wn += strlen(join_pcs[idx[k]]);
				}
				exact(&s, list, (size_t)w, want, wn, "join", cases++);
				hexs(want, wn, hx);
				if (ap) {
					line = next_line(&ap);
					pyn++;
					if ((!line || strcmp(line, hx)) && bad++ < 5u)
						printf("  FAIL join vs python: ours %s theirs %s\n", hx, line ? line : "(none)");
				}
				if (aq) {
					line = next_line(&aq);
					pln++;
					if ((!line || strcmp(line, hx)) && bad++ < 5u)
						printf("  FAIL join vs perl: ours %s theirs %s\n", hx, line ? line : "(none)");
				}
			}
		}
	free(py);
	free(pl);
	CKF(!bad, "join vs python/perl: %lu differences", bad);
	printf("  join: %lu cases against the reference, %lu against python 3 (str.join), %lu against perl (join)\n", cases, pyn, pln);
}

static void list_corrupt(void)
{
	uint8_t list[64];
	uint64_t w = 0, p;
	size_t cut;
	struct kuncoat_step s = mk(KUNCOAT_ALGO_JOIN, 0, 0, (const uint8_t *)",", 1);

	kof_strlist_put(list, &w, (const uint8_t *)"ab", 2);
	kof_strlist_put(list, &w, (const uint8_t *)"", 0);
	kof_strlist_put(list, &w, (const uint8_t *)"c", 1);
	for (cut = 0; cut < w; cut++) {
		enum kuncoat_status st = T(&s, list, cut, 64, &p);
		/* a cut at a piece boundary is a shorter list and is fine; any other is corrupt */
		int boundary = cut == 0 || cut == 6 || cut == 10;

		CKF(boundary ? st == KUNCOAT_OK : st == KUNCOAT_CORRUPT, "join of a list cut at %zu: status %d", cut, (int)st);
	}
	list[0] = 0xff;                         /* a length that runs past the buffer */
	CKF(T(&s, list, w, 64, &p) == KUNCOAT_CORRUPT, "join of a list whose first length is past the end");
	{
		struct kuncoat_step z = mk(KUNCOAT_ALGO_JOIN, 0, 0, NULL, 0);
		uint8_t l2[16];
		uint64_t w2 = 0;

		kof_strlist_put(l2, &w2, (const uint8_t *)"x", 1);
		kof_strlist_put(l2, &w2, (const uint8_t *)"y", 1);
		CKF(T(&z, l2, w2, 8, &p) == KUNCOAT_OK && p == 2 && !memcmp(res, "xy", 2), "join with no key is the elements run together");
	}
	{
		struct kuncoat_step z = mk(KUNCOAT_ALGO_SPLIT, 0, 0, NULL, 0), y = mk(KUNCOAT_ALGO_SPLIT, 0, 0, (const uint8_t *)"", 0);

		CKF(T(&z, (const uint8_t *)"abc", 3, 64, &p) == KUNCOAT_BAD_ARG, "split with no key");
		CKF(T(&y, (const uint8_t *)"abc", 3, 64, &p) == KUNCOAT_BAD_ARG, "split with an empty key");
	}
}

/* ---- REPEAT ------------------------------------------------------------------------------ */

static const char py_repeat[] =
	"import itertools\n"
	"for ln in range(0,5):\n"
	"  for t in itertools.product('ab',repeat=ln):\n"
	"    s=''.join(t)\n"
	"    for n in range(0,8):\n"
	"      print((s*n).encode().hex())\n";

static const char pl_repeat[] =
	"for my $ln(0..4){for my $i(0..2**$ln-1){my $s='';for my $k(0..$ln-1){$s.=(($i>>($ln-1-$k))&1)?'b':'a';}\n"
	"for my $n(0..7){print unpack('H*',$s x $n),\"\\n\";}}}\n";

static void repeat_all(void)
{
	char *py = run_script(1, py_repeat), *pl = run_script(0, pl_repeat), *ap = py, *aq = pl;
	unsigned long cases = 0, bad = 0;
	unsigned ln, idx, rep;

	for (ln = 0; ln <= 4u; ln++)
		for (idx = 0; idx < (1u << ln); idx++) {
			uint8_t sub[8], want[64];
			unsigned k;

			/* product varies the last letter fastest: letter k of the word is bit (ln-1-k) of its index */
			for (k = 0; k < ln; k++)
				sub[k] = (idx >> (ln - 1u - k) & 1u) ? 'b' : 'a';
			for (rep = 0; rep <= 7u; rep++) {
				struct kuncoat_step s = mk(KUNCOAT_ALGO_REPEAT, 0, rep, NULL, 0);
				size_t wn = 0;
				char hx[200], *line;

				for (k = 0; k < rep; k++) {
					memcpy(want + wn, sub, ln);
					wn += ln;
				}
				exact(&s, sub, ln, want, wn, "repeat", cases++);
				hexs(want, wn, hx);
				if (ap && (!(line = next_line(&ap)) || strcmp(line, hx)))
					bad++;
				if (aq && (!(line = next_line(&aq)) || strcmp(line, hx)))
					bad++;
			}
		}
	free(py);
	free(pl);
	CKF(!bad, "repeat vs python/perl: %lu differences", bad);
	printf("  repeat: %lu cases (words to 4 bytes, counts 0..7)%s%s\n", cases, py ? ", python 3 s * n agrees" : "", pl ? ", perl x agrees" : "");
	{
		/* the product is checked before a byte is written: four billion copies of a long subject is a refusal, not a loop */
		struct kuncoat_step s = mk(KUNCOAT_ALGO_REPEAT, 0, 0xffffffffu, NULL, 0);
		uint64_t p;
		uint8_t big[1000];

		memset(big, 'a', sizeof big);
		CKF(T(&s, big, sizeof big, BIG, &p) == KUNCOAT_OVER_BUDGET, "repeat four billion times is over budget");
		s = mk(KUNCOAT_ALGO_REPEAT, 0, 0, NULL, 0);
		CKF(T(&s, big, 10, 1, &p) == KUNCOAT_OK && p == 0, "repeat zero times is empty");
	}
}

/* ---- REPLACE with FIRST and ICASE ------------------------------------------------------------ */

/* The answer built from the matches: where every match is, then the text between them. */
static size_t ref_replace(const uint8_t *in, size_t n, const uint8_t *se, size_t sn, const uint8_t *re, size_t rn, int first, int icase, uint8_t *out)
{
	size_t at[64], nm = 0, i, k, w = 0, from = 0;

	for (i = 0; i + sn <= n && !(first && nm);) {
		int hit = 1;

		for (k = 0; k < sn && hit; k++) {
			uint8_t a = in[i + k], b = se[k];

			if (icase) {
				a = (uint8_t)(a >= 'A' && a <= 'Z' ? a + 32 : a);
				b = (uint8_t)(b >= 'A' && b <= 'Z' ? b + 32 : b);
			}
			hit = a == b;
		}
		if (hit) {
			at[nm++] = i;
			i += sn;
		} else {
			i++;
		}
	}
	for (k = 0; k < nm; k++) {
		memcpy(out + w, in + from, at[k] - from);
		w += at[k] - from;
		memcpy(out + w, re, rn);
		w += rn;
		from = at[k] + sn;
	}
	memcpy(out + w, in + from, n - from);
	return w + (n - from);
}

static const char py_replace[] =
	"import re\n"
	"def word(al,idx,ln):\n"
	"    o=''\n"
	"    for _ in range(ln):\n"
	"        o+=al[idx%len(al)]; idx//=len(al)\n"
	"    return o\n"
	"al='abA'\n"
	"for fl in range(4):\n"
	"  for sl in range(7):\n"
	"    for si in range(3**sl):\n"
	"      s=word(al,si,sl)\n"
	"      for sel in range(1,3):\n"
	"        for sei in range(3**sel):\n"
	"          se=word(al,sei,sel)\n"
	"          for rep in ['','x','xy']:\n"
	"            cnt=1 if fl&2 else 0\n"
	"            if fl&1: r=re.sub(re.escape(se),lambda m:rep,s,count=cnt,flags=re.I)\n"
	"            else: r=s.replace(se,rep,cnt) if cnt else s.replace(se,rep)\n"
	"            print(r.encode().hex())\n";

static const char pl_replace[] =
	"sub word{my($al,$idx,$ln)=@_;my $o='';for(1..$ln){$o.=substr($al,$idx%length($al),1);$idx=int($idx/length($al));}return $o;}\n"
	"my $al='abA';\n"
	"for my $fl(0..3){for my $sl(0..6){for my $si(0..3**$sl-1){my $s0=word($al,$si,$sl);for my $sel(1..2){for my $sei(0..3**$sel-1){my $se=word($al,$sei,$sel);\n"
	"for my $rep('','x','xy'){my $s=$s0;my $q=quotemeta($se);\n"
	"if(($fl&1)&&($fl&2)){$s=~s/$q/$rep/i;}elsif($fl&1){$s=~s/$q/$rep/gi;}elsif($fl&2){$s=~s/$q/$rep/;}else{$s=~s/$q/$rep/g;}\n"
	"print unpack('H*',$s),\"\\n\";}}}}}}\n";

static void replace_all(void)
{
	static const char *const reps[] = { "", "x", "xy" };
	char *py = run_script(1, py_replace), *pl = run_script(0, pl_replace), *ap = py, *aq = pl;
	unsigned long cases = 0, bad = 0;
	unsigned fl, sl, si, sel, sei, r;

	for (fl = 0; fl < 4u; fl++)
		for (sl = 0; sl <= 6u; sl++)
			for (si = 0; si < ipow(3, sl); si++) {
				uint8_t sub[8];

				word("abA", sub, si, sl);
				for (sel = 1; sel <= 2u; sel++)
					for (sei = 0; sei < ipow(3, sel); sei++) {
						uint8_t se[4];

						word("abA", se, sei, sel);
						for (r = 0; r < 3u; r++) {
							uint8_t key[8], want[64];
							uint32_t flags = ((fl & 1u) ? KUNCOAT_F_ICASE : 0u) | ((fl & 2u) ? KUNCOAT_F_FIRST : 0u);
							size_t rl = strlen(reps[r]), wn;
							struct kuncoat_step s;
							char hx[200], *line;

							memcpy(key, se, sel);
							memcpy(key + sel, reps[r], rl);
							s = mk(KUNCOAT_ALGO_REPLACE, flags, sel, key, (uint32_t)(sel + rl));
							wn = ref_replace(sub, sl, se, sel, (const uint8_t *)reps[r], rl, (fl & 2u) != 0, (fl & 1u) != 0, want);
							exact(&s, sub, sl, want, wn, "replace", cases++);
							hexs(want, wn, hx);
							if (ap && (!(line = next_line(&ap)) || strcmp(line, hx)))
								bad++;
							if (aq && (!(line = next_line(&aq)) || strcmp(line, hx)))
								bad++;
						}
					}
			}
	free(py);
	free(pl);
	CKF(!bad, "replace (first / ignore case) vs python/perl: %lu differences", bad);
	printf("  replace: %lu cases of FIRST and ICASE%s%s\n", cases, py ? ", python 3 str.replace(.., 1) and re.sub(IGNORECASE) agree" : "", pl ? ", perl s/// agrees" : "");
}

/* ---- TRIM with a set ------------------------------------------------------------------------ */

static const char py_trim[] =
	"import itertools\n"
	"for sl in range(7):\n"
	"  for t in itertools.product('a \\t_',repeat=sl):\n"
	"    s=''.join(t)\n"
	"    for st in [' ',' \\t','a_','']:\n"
	"      for side in (1,2,3):\n"
	"        r=s.strip(st) if side==3 else (s.lstrip(st) if side==1 else s.rstrip(st))\n"
	"        print(r.encode().hex())\n";

static void trim_sets(void)
{
	static const char *const sets[] = { " ", " \t", "a_", "" };
	char *py = run_script(1, py_trim), *ap = py;
	unsigned long cases = 0, bad = 0;
	unsigned sl, idx, st, side, k;

	for (sl = 0; sl <= 6u; sl++)
		for (idx = 0; idx < ipow(4, sl); idx++) {
			uint8_t sub[8];

			for (k = 0; k < sl; k++)        /* the last letter varies fastest, as in itertools.product */
				sub[k] = (uint8_t)"a \t_"[(idx / ipow(4, sl - 1u - k)) % 4u];
			for (st = 0; st < 4u; st++)
				for (side = 1; side <= 3u; side++) {
					size_t sn = strlen(sets[st]), b = 0, e = sl;
					struct kuncoat_step s = mk(KUNCOAT_ALGO_TRIM, 0, side, (const uint8_t *)sets[st], (uint32_t)sn);
					char hx[64], *line;

					while ((side & 1u) && b < e && sn && memchr(sets[st], sub[b], sn))
						b++;
					while ((side & 2u) && e > b && sn && memchr(sets[st], sub[e - 1u], sn))
						e--;
					exact(&s, sub, sl, sub + b, e - b, "trim set", cases++);
					hexs(sub + b, e - b, hx);
					if (ap && (!(line = next_line(&ap)) || strcmp(line, hx)))
						bad++;
				}
		}
	free(py);
	CKF(!bad, "trim with a set vs python strip/lstrip/rstrip(chars): %lu differences", bad);
	printf("  trim: %lu cases with a set%s\n", cases, py ? " (python 3 strip(chars) agrees)" : "");
}

int main(void)
{
	setvbuf(stdout, NULL, _IONBF, 0);
	if (!hv_gb_init(&gin, BIG) || !hv_gb_init(&gout, BIG)) {
		printf("strfn_lists: cannot map guard buffers\n");
		return 1;
	}
	split_all();
	join_all();
	list_corrupt();
	repeat_all();
	replace_all();
	trim_sets();
	if (skipped_py || skipped_pl)
		printf("  SKIPPED against an interpreter: python3 %u, perl %u (the reference still ran)\n", skipped_py, skipped_pl);
	hv_gb_free(&gin);
	hv_gb_free(&gout);
	return hv_done("strfn_lists");
}
