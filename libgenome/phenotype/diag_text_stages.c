/*
 * diag_text_stages.c - WHICH ALGORITHM A LANGUAGE GETS: the table of the relation layer's stages, keyed by language row.
 *
 * The stages answer different misses and a language is given the ones its measured misses call for, not all of them: a stage that gains nothing for a language still costs its pass, and
 * one that adds wrong links there is worse than none. Each row says what was measured (the corpora of the TEXT route, 2026-10-21: s3 {php 76, asp 17, aspx 5, jsp 5, cfm 3, py 1, pl 2,
 * cgi 2}, dx/malc 47, dx/benfarm 13392, wpcheck 1073, work2/scripts 78 php 109 sh 34 py ..., wire_b/lists {js 4000, py 1751, perl 2673, ruby 3000, lua 357, jsp 35, aspx 45, sh 3166,
 * bat 2642, psh 124, vbs 34, asp 283, cfm 4, tcl 127}, kofsurvey/sc_fam 1312 sh): the links ADDED over the tree before the stages, and for the ones that were read, how many were
 * real. A language with no sample says so; its row is the one its syntax allows and is untested on a program.
 *
 *   SUM    parameter summaries and the return flow (diag_text_sum.c): the language has functions with a parameter list and a return, and a request reaches a command through one
 *   FIELD  `obj.field = v` gives the object what v holds (diag_text.c, field_target): the language writes an object's inputs one member at a time (`psi.Arguments = "/c " + arg`)
 *   PATH   two nodes that name the same constant path are one object, a SHARED link (diag_text_ident.c): the language writes a program's steps as commands on files
 */

#include "diag_text_private.h"

struct stage_row {
	uint32_t lang;
	unsigned stages;
};

static const struct stage_row table[] = {
	/* php: SUM +696 may links on the 76 s3 shells (+682 on dx/malc's 47, the same kind of file), +57 on wordpress's 1073 files and +24 on 13392 clean ones; 22 read: 13 real, 9 cannot tell,
	 * none wrong. FIELD not chosen: no sample of the shape. PATH not chosen: 0 added (a php path is nearly always a variable the evaluator does not hold constant). */
	{ KGENOME_TEXTUAL_LANG_PHP,  KGENOME_DTX_ST_SUM },
	/* js: SUM +327 may links on 4000 files, 318 of them in four webpack bundles (a module loader called from everywhere: data-call -> data-call; they also fill the four inputs of a node,
	 * which the scan says as TRUNCATED), 9 elsewhere (2 read, real). FIELD measured and refused: `fs.rename = function ..` is monkey patching, it joined 3 of 10 nodes of a module to each
	 * other (wrong). PATH: 0 added. */
	{ KGENOME_TEXTUAL_LANG_JS,   KGENOME_DTX_ST_SUM },
	/* python: SUM +30 may on 1785 files (the wrapper `def run(cmd): subprocess.call(cmd, shell=True)` fed by urlopen / b64decode); the 18 of work2 read, all real. PATH +1 (shutil.copyfile
	 * to a constant, os.unlink of the same: real). FIELD refused with js: `self.x = v` is not an object being built. */
	{ KGENOME_TEXTUAL_LANG_PY,   KGENOME_DTX_ST_SUM | KGENOME_DTX_ST_PATH },
	/* perl: the row has no parameter list (`my ($a) = @_` is not read), so SUM can only return: +0 on 2678 files. PATH +1 (copy to a constant, chmod of it: read, real). */
	{ KGENOME_TEXTUAL_LANG_PERL, KGENOME_DTX_ST_SUM | KGENOME_DTX_ST_PATH },
	/* ruby: SUM +3 on 3000 files (read: 1 real, 2 cannot tell). lua: +2 on 357 (read: cannot tell). tcl has no stage: its procs are commands (`proc f {a} {}`, called `f x`) and the command
	 * walk does not take a user function through; not done, and the 127 tcl files hold one node in all, so no sample would show it. */
	{ KGENOME_TEXTUAL_LANG_RUBY, KGENOME_DTX_ST_SUM },
	{ KGENOME_TEXTUAL_LANG_LUA,  KGENOME_DTX_ST_SUM },
	/* jsp: SUM +7 on 35 files (read: 4 real, 3 cannot tell). aspx: SUM +8 may on 45 + 5 files and FIELD +1 must: the shells whose command goes through a method (009_aspx_bypass_av,
	 * 019_cmdasp, 075_cmdasp and their copies) now have input-request -> proc-start; `psi.Arguments = "/c " + arg` needs FIELD. All 8 read, real. */
	{ KGENOME_TEXTUAL_LANG_JSP,  KGENOME_DTX_ST_SUM },
	{ KGENOME_TEXTUAL_LANG_ASPX, KGENOME_DTX_ST_SUM | KGENOME_DTX_ST_FIELD },
	/* asp / vbs: SUM +3 on 300 asp files (015_newaspcmd: `getCommandOutput("cmd /c" & szCMD)` -> exec, its copy, and an upload page: real) and +4 on 34 vbs files (obfuscated Eval functions: cannot
	 * tell); it needs the Function scopes (BLK_PAIR, `Dim`, undeclared = global), which are the row's and not a stage. FIELD: COM objects are built member by member (`stream.Type = 1`):
	 * no corpus link needs it, the literal tests do. PATH on vbs: a file made by CreateTextFile and run by WScript.Shell.Run is the shape of the 18 hta samples (not scanned here: html). */
	{ KGENOME_TEXTUAL_LANG_ASP,  KGENOME_DTX_ST_SUM | KGENOME_DTX_ST_FIELD },
	{ KGENOME_TEXTUAL_LANG_VBS,  KGENOME_DTX_ST_SUM | KGENOME_DTX_ST_FIELD | KGENOME_DTX_ST_PATH },
	/* sh: SUM gave 0 on 109 files (the functions are `f() { .. }` called as commands, `$1` the parameter: the command walk does not take them); path identity is what the droppers miss: +9157 shared
	 * links on the 1312 sc_fam files (`wget URL; chmod +x f; ./f` and `base64 -d > f; bash f`, repeated per architecture), +142 on 120 sample droppers, +224 on 3166 files; 25 read, all real.
	 * bat: PATH added nothing in 2663 files (no dropper there names a path twice in the nodes the table has); the row is kept for curl -o. psh: +1 of 134 files (WriteAllBytes(path)
	 * then Start-Process path: read, real). */
	{ KGENOME_TEXTUAL_LANG_SH,   KGENOME_DTX_ST_PATH },
	{ KGENOME_TEXTUAL_LANG_BAT,  KGENOME_DTX_ST_PATH },
	{ KGENOME_TEXTUAL_LANG_PSH,  KGENOME_DTX_ST_PATH },
};

unsigned kgenome_dtx_stages(uint32_t lang)
{
	uint32_t i;

	for (i = 0; i < sizeof table / sizeof table[0]; i++)
		if (table[i].lang == lang)
			return table[i].stages;
	return 0;
}
