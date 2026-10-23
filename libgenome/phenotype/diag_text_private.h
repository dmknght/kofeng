/*
 * diag_text_private.h - what the two halves of the TEXT route share: the tokens and variables the walk (diag_text.c) builds, and
 * the constant evaluator (diag_text_eval.c) that reads a name or a payload out of them. NOT PART OF THE SURFACE.
 */

#ifndef KGENOME_DIAG_TEXT_PRIVATE_H
#define KGENOME_DIAG_TEXT_PRIVATE_H

#include <string.h>

#include "diag_oatab.h"
#include "diag_scan_private.h"
#include <textual/textual.h>

#define KGENOME_DTX_FRAMES_FIRST 32u     /* the frames a walk starts with: the table doubles with the bracket depth of the text, charged to the scan (G18: it stopped at 4096 and said nothing) */
#define KGENOME_DTX_DEFS   6u            /* producers kept for one variable: the latest ones */
#define KGENOME_DTX_PDEFS  4u            /* slots of summaries kept for one variable: the latest ones */
#define KGENOME_DTX_CAPC      2048u    /* slots of the memo of table lookups (a power of two) */
#define KGENOME_DTX_CAPC_NAME 22u      /* the longest name it holds */
#define KGENOME_DTX_NAME   64u           /* a name is looked up in a buffer of this many bytes; one that does not fit is refused (no row is longer than 46) */

struct kgenome_dtx_capc {
	uint16_t cap;
	uint16_t id;            /* the name's id (kgenome_nucleo_name_lookup), so the spelling is a read and not a second search */
	uint8_t  len;           /* 0: empty */
	char     name[KGENOME_DTX_CAPC_NAME];
};

/*
 * A PRODUCER is a node of the scan (an index below this) or a SLOT of a summary (this and above): what a function's parameter holds before a call has said what it is, and
 * what a function returns before the call has been read. Held where a node is held - in a variable's `def`, in the walk's lists - and told apart by this one number. See diag_text_sum.c.
 */
#define KGENOME_DTX_PSEUDO 0x10000u

/* The stages of the relation layer a language row may use (diag_text_stages.c: the table, and the measurement that put each language in it). */
enum kgenome_dtx_stage {
	KGENOME_DTX_ST_SUM   = 1u,      /* parameter summaries and the return flow */
	KGENOME_DTX_ST_FIELD = 2u,      /* `obj.field = v` gives the object what v holds */
	KGENOME_DTX_ST_PATH  = 4u       /* two nodes that name the same constant path are one object (a shared link) */
};

struct kgenome_dtx_sum;
struct kgenome_dtx_ident;

struct kgenome_dtx_tok {
	uint32_t off, len;
	/* 'I' name, 'V' variable (a sigil language: without its "$"; any other: a name that is not a call, a member or a keyword),
	 * 'S' literal, 'g' the name of a tag that is a call (its attributes follow, to the 'T' of its ">"), 'c' a string that runs a command and 'b' a block of code that stands where a value is (their `open`:`close` is how many tokens follow that are inside them: see diag_text_interp.c), 'P' punctuation, 'T' the end of a statement the text does not write as a byte (a line break, the end of an island:
	 * only in a language whose row says so, see kgenome_dtx_lang.eol_term; len is 0) */
	uint8_t  k;
	uint8_t  open, close;   /* 'S': the delimiters' lengths */
	uint8_t  fl;            /* 'S': the span's KGENOME_TEXTUAL_F_* */
};

/*
 * A stretch of tokens, [rs, re): the right side of an assignment, or of one `.=` that follows it. The pieces of one variable are a list (`next`: the index + 1 of the one after, 0 for the
 * last) in the text's arena (struct kgenome_dtx.seg): a variable built from a hundred appends has a hundred of them, as many as the text writes (G4: it kept six and called the rest
 * "not constant", so a name written in seven pieces was no name). The arena is charged to the scan like every table that grows with the text.
 */
struct kgenome_dtx_seg {
	uint32_t rs, re, next;
};

/*
 * A VARIABLE KEEPS WHERE ITS VALUE IS WRITTEN and not the value: the right sides of its assignments, as token ranges. A value is
 * made on demand, by the one function that can (kgenome_dtx_eval_*), when something asks what a name is - the callee of `$f(...)`. A
 * variable that holds a megabyte of payload costs nothing until a decoder's argument is read, and a variable nobody asks about
 * is never evaluated.
 */
struct kgenome_dtx_var {
	const uint8_t *name;
	uint32_t       len, hash;
	uint32_t       scope;          /* the function body it lives in, 0 for the top of the file */
	uint16_t       def[KGENOME_DTX_DEFS];   /* the nodes whose value flowed into it (a node index is 16 bits: KGENOME_MAX_INDEX) */
	/* The SLOTS of summaries it holds (KGENOME_DTX_PSEUDO and above, diag_text_sum.c) are kept apart: a slot that shared `def` pushed the oldest NODE out of the six, and a link the walk
	 * made before was gone (measured: alfa's `$shell = f($shell)` lost the request that `$shell` had held). Nodes keep their six whatever slots a variable has. */
	uint32_t       pdef[KGENOME_DTX_PDEFS];
	uint8_t        n_def, n_pdef;
	uint8_t        n_set, n_app;   /* the assignments (`=`) and the appends (`.=`, `+=`) written to it, saturating: how many programs' worth of values it holds */
	uint8_t        lost;           /* a producer was pushed out of `def` or `pdef` by a newer one: the variable is read with less than it was given, and a read says so (kgenome_dtx_cut) */
	uint8_t        unknown;        /* a right side it could not keep (the arena was refused room: said, and the route stops) */
	uint32_t       nseg;           /* the pieces of its value: the right side of the last `=`, then each `.=` since */
	uint32_t       seg_head, seg_tail;     /* the first and last piece, as index + 1 into the text's arena; 0 none */
};

/*
 * A NAME THAT IS ANOTHER SCOPE'S VARIABLE: `global $a` in a function is the top level's $a, and the variable a closure lists in
 * `use ($a)` is the one of the scope the closure was written in. Kept in ONE open-addressing table keyed by (scope, name) (alt), so that finding one costs a probe whatever
 * the scope holds: a chain per scope cost every lookup the aliases of the scope, and `global v0, v1, ... v5999` made every read of a variable of that function walk 6000
 * entries (S2-1: 120 million blocks at 32 KiB, 1.26 billion at 128 KiB). `same` links an alias to the OLDER one of the same key, so the search still finds the newest first
 * (a chain per scope searched newest first, filtered by the name, is the same sequence).
 */
struct kgenome_dtx_alias {
	const uint8_t *name;
	uint32_t       len, target, scope, hash, same;
};

/*
 * THE CODE A SCRIPT COMPUTES: a text the evaluator reads out of the program as a constant and that is handed to something that runs
 * it (eval, create_function). It is lexed as code and walked in the same scan, so what hoho.php assembles with str_replace out of
 * eight variables is analysed as the program it is. `room` is the bytes of such code still allowed, over every layer of one scan.
 */
struct kgenome_dtx_layers {
	uint64_t room;
	struct kgenome_diag_text_work work;     /* what every layer of the scan cost, summed (kgenome_diag_text_req.work) */
};

/* A right side the walk met, kept to be evaluated when every assignment of the file is known: tokens [rs, re). */
struct kgenome_dtx_cand {
	uint32_t rs, re;
};


/*
 * WHAT A CALL DOES WITH ITS ARGUMENTS, as data: one row per function whose arguments do not all mean the same thing. Everything
 * else is read the one way - a value in an argument flows into the call's result - and that is what the walk does with a call
 * that has no row. The rows are the language's (kgenome_dtx_lang.callsem), by the spelling the table has for the call.
 *
 *   OUT      the call writes an argument: `preg_match($re, $subject, $m)` makes no value the program uses, it puts what it took from
 *            the subject into $m, and a payload read from the request reaches `$m[1]` and from there a decode and an eval. `src` is
 *            the arguments it reads (a bit mask), `dst` the one it writes.
 *   CLEAN    the result is a value of another KIND than its argument - a number, a hex digest, a length, a truth value - and no
 *            sender can make it a command, a path or code: `md5($_GET['x'])` is not the request, and a value that went through it
 *            does not reach what runs. Nothing flows out of the call.
 *   `val`    the argument a node acts on, when it is not the first: create_function($args, $code) runs its SECOND argument. The
 *            arguments of eval, assert, call_user_func and the decoders other than this one are what they are handed, data for the
 *            callee: a request value in `register_shutdown_function('f', $k)` is an argument of f, not what runs.
 */
#define KGENOME_DTX_CS_OUT    1u
#define KGENOME_DTX_CS_NO_DST 0xffu     /* an OUT call that writes no argument: extract() writes variables by NAME */
#define KGENOME_DTX_CS_CLEAN  2u

struct kgenome_dtx_callsem {
	const char *name;
	uint8_t     flags;
	uint8_t     src;        /* OUT: the arguments it reads */
	uint8_t     dst;        /* OUT: the argument it writes */
	uint8_t     val;        /* the argument a node acts on */
};

/*
 * A CALL THAT MAKES AN OBJECT OF A CLASS A LITERAL NAMES - `CreateObject("WScript.Shell")`, `new ActiveXObject("MSXML2.XMLHTTP.6.0")`, `New-Object -ComObject
 * WScript.Shell`, `createObject("java", "java.lang.Runtime")` - as data, one row per such call of the language. The class is what a member called on the
 * object is qualified by (`o.Run` is "WScript.Shell.Run"), and its table is not always the language's own: COM is written once, in the VBS table, and every
 * language that reaches a COM object looks the member up there (`target`), a java object of cfml is a row of the java table.
 *
 *   arg      the argument that holds the class: a literal, or any constant the evaluator follows (the first by default)
 *   type     1 + the argument that must say which kind of object it is (cfml's "java"), 0 none; `type_word` is what it must be
 *   versions the class is written with a version number the table's row has not ("MSXML2.XMLHTTP.6.0"): trailing all-digit pieces are dropped
 *   bare     the call is a command (powershell): the class is the first word after its options, and `flag` among them says which table
 */
struct kgenome_dtx_classfn {
	const char *name;
	uint8_t     arg, type;
	const char *type_word;
	unsigned    target;
	uint8_t     versions;
	uint8_t     bare;
	const char *flag;
	uint8_t     ns_drop;    /* the class is written with its package ("java.lang.Runtime") and the table spells it without: looked up one piece at a time */
};

/*
 * THE CONDITION OF A STATEMENT A COMMAND FOLLOWS, `if exist f cmd`, `if not "%a%"=="b" cmd` (batch): the words that begin it (`head`), the ones that may precede its test
 * (`mods`: `not`, besides the options), the tests that take one operand (`unary`: exist defined errorlevel) and the comparison words between two (`binary`; "==" always is one).
 * The command is the token after them; their operands are skipped, not read.
 */
struct kgenome_dtx_cond {
	const char *const *head, *const *mods, *const *unary, *const *binary;
};

/*
 * WHAT A CALL TAKES AS A FILE, as data (diag_text_ident.c): one row per command or call whose arguments name a file in a place the text does not make plain. A word that has a path's shape
 * (a separator, or a name and an extension) is a path wherever it stands; a bare name (`a`, `arm`) is one only here.
 *   opts      the options whose value is a file, separated by spaces ("-O" for wget: the word after it, or glued to a short one)
 *   pos       1: the first word that is no option is a file (an interpreter's script), 2: the last (chmod's file)
 *   implicit  the call names no file but makes one: the last piece of the URL it is given (wget with no -O)
 *   implicit_opt  the option that makes it do so (curl -O); NULL when it always does
 */
struct kgenome_dtx_pathsem {
	const char *name;
	const char *opts;
	uint8_t     pos;
	uint8_t     implicit;
	const char *implicit_opt;
	const char *text_opt;   /* the options after which the first word is text and not a file (an interpreter's `-c`): `pos` does not apply */
};

/* How a language delimits the body of a function, for the scope of its variables (diag_text_scope.c). */
enum kgenome_dtx_blocks {
	KGENOME_DTX_BLK_BRACE = 0,      /* `function f(...) {`: php, js, perl's `sub`; and, where the row says `shape`, a `name(...) {` */
	KGENOME_DTX_BLK_INDENT,         /* the lines more indented than the `def` (python) */
	KGENOME_DTX_BLK_END,            /* up to the `end` that matches, counting the words that open a block (lua, ruby) */
	KGENOME_DTX_BLK_PAIR            /* `Function`/`Sub` up to the `End Function`/`End Sub` that names the same word (vbscript: its other blocks close with `End If`, `Next`, `Loop`, so no one word pairs them) */
};

/*
 * THE LANGUAGE PROFILE: what the one walk (diag_text.c) and the one evaluator (diag_text_eval.c) ask of the language they read, as data -
 * one row per language the route serves, each in its own file (diag_text_lang_<name>.c), listed once in diag_text_lang.c. A language is
 * served when it has a row; the engine asks that and nothing else (kgenome_diag_text_serves).
 *
 * The lists are NULL ended. Everything the walk used to assume was php is a field here, and php's row holds exactly what the walk assumed
 * (the lists of the corpus in the tests did not move when this was made). What the data cannot say is a `hook` - a small named function
 * of the row - and each says why where it is written.
 */
struct kgenome_dtx_lang {
	uint32_t    id;         /* KGENOME_TEXTUAL_LANG_*: the lexer, and the literals' value */
	uint32_t    lit_lang;   /* the language whose lexer row reads this one's literals, when its own has no value rule (classic asp: vbscript's), else 0 */
	unsigned    target;     /* the nucleo target whose table the names are rows of (and whether they fold: the table says it) */
	/* ---- how a name is written ---- */
	uint8_t     fold;       /* names are not case sensitive: the table's own `fold` (php, .NET); the walk's keywords follow it */
	uint8_t     fold_vars;  /* variables are not case sensitive either (vb: `objShell` and `objshell`); php's are, whatever its functions' names do */
	uint8_t     sigil;      /* '$' when a variable is written with it (php, perl); 0 when a bare name is one */
	uint8_t     ident_bs;   /* a backslash is part of a name (php's namespaces) */
	const char *ident_extra;/* other bytes a name may hold: "$" in js and java */
	const char *ident_pre;  /* bytes that may begin a bare variable and are part of its name: ruby's "@" and "$" */
	const char *const *keywords;    /* bare-variable languages: words that are no variable (`return`, `end`, `new`) */
	/* ---- how a value is built ---- */
	const char *append;     /* the operator that adds to a variable ".=", "+=": the pieces of its value; NULL none */
	const char *const *concat;      /* the operators that join two strings in an expression: "." for php, ".." for lua; NULL none */
	uint8_t     string_call;    /* a variable holding a string is called by that name (php: `$f('x')` calls the function $f names): kgenome_diag_text_req.on_head */
	uint8_t     adjacent;   /* two literals side by side are one (python's "a" "b") */
	/* How a LIST of values is written, where the function table has an operation on lists (join, split): the evaluator reads the elements of `[a, b]` (js, python, ruby), of a bracket
	 * that holds a comma `(a, b)` (python's tuple, powershell's array) and of `@(a, b)` (powershell). A list is no string constant: it is a value only a join or a split's
	 * answer consumes, and one left over makes the expression not constant. */
	uint8_t     list_bracket;
	uint8_t     list_paren;
	uint8_t     list_at;
	const char *list_call;  /* a call that makes a list of its arguments: php's `array(a, b)` */
	uint8_t     typed;      /* a number is not a string: "+" of two numbers adds (js, python, ruby, powershell, java, c#), and a constant that is only numbers is
				 * not a string constant. Not php, whose "." makes a string of anything: the lists measured with php stay as they were. */
	/* ---- how a qualified name is written ---- */
	const char *const *joins;       /* what joins a qualifier to a name: ".", "::", "->" (php's "->" is only a member: see `chain`) */
	uint8_t     data_call;  /* a variable may be called, `f(x)` where f holds a name or a function: a node of data-call when the program or the sender made it (not vb: a function's name is
				 * assigned its result there, and calling it is no call of a value) */
	uint8_t     chain;      /* a call's name is its whole qualified chain, read by diag_text_chain.c ("os.system"), a receiver that is
				 * itself a call is dropped (`Runtime.getRuntime().exec` is "Runtime.exec") and a request is a member
				 * ("request.args"); 0: a call is the one name in front of its bracket (php's method `$o->system(` is a call of system) */
	uint8_t     hash_key;   /* perl: `$ENV{KEY}` is the member "ENV.KEY" */
	uint8_t     typed_decl; /* `File f = ...`: the type in front of a variable is the class of its object (java, c#) */
	uint8_t     ns_drop;    /* a name written with its namespace ("System.Diagnostics.Process.Start", "java.lang.Runtime.exec") is looked up without
				 * the leading pieces, one at a time, until a row has it: the table spells the class and the member (java, .NET) */
	const char *module_fn;  /* the function that names a module by a literal: `require('child_process')`, `__import__('os')`; its result is that
				 * module, so `require('child_process').exec` is "child_process.exec" and `cp = require(..)` makes `cp.exec` the same */
	const char *const *scope_objs;  /* `window[n](...)`: a subscript of these is a call by a value (js) */
	const char *const *load_names;  /* a call of these whose argument is not a literal loads a module named by a value: told as "(load)" */
	/* ---- statements ---- */
	uint8_t     eol_term;   /* a line break ends a statement (python, ruby, lua, js's automatic semicolon, vb): the token stream gets a 'T' */
	uint8_t     island_term;    /* the end of an island of code (a page's <% %>) ends one too */
	uint8_t     cont_us;    /* a lone "_" ends a line that goes on (vb) */
	uint8_t     kwargs;     /* `f(name=value)` names an argument and assigns nothing (python) */
	const char *const *num_casts;   /* "(int)" and its kin, a cast whose operand is a number */
	const char *const *stmt_words;  /* names that are a call without a bracket - `include "f"`, `system "id"`, `Execute x`: its arguments run to the statement's end */
	const char *const *stmt_block;  /* what follows such a name that is a block and not its argument: perl's `eval {`, ruby's `eval do` and `{` */
	uint8_t     bare_members;       /* a member that is a row is a node with or without a bracket (vb: `o.Run cmd, 0`, `Request.Form`, `x.nodeTypedValue`); at the head of a statement
					 * its arguments run to the end of it */
	uint8_t     sep;        /* a byte that ends a statement besides ";" (vb's ":") */
	const char *const *stmt_lead;   /* words a statement follows: vb's `then`, `else`, `call` */
	const char *const *cmd_str;     /* openers of a string that is a COMMAND LINE the shell runs, as written ("`", "qx", "%x"); the row names what it is (`cmd_row`) */
	const char *cmd_row;    /* the table's name for running one: perl "readpipe", ruby "system", php "shell_exec" */
	uint8_t     interp_all; /* every string that interpolates is read for the code it holds, not only a command string (sh, powershell, cfml: their strings are how they build commands) */
	uint8_t     interp;     /* a string that interpolates is read for the code it holds: "$x", "${x}", "$h{k}" (1), "#{expr}" (2), "$(cmd)" and "`cmd`" in sh (3), "#expr#" in cfml (4) */
	const char *body_stream;        /* a read of the request's own body: the stream a file-open names (php's "php://input") */
	/* ---- objects of a class a call names (COM, java objects) ---- */
	const struct kgenome_dtx_classfn *classfns;
	uint32_t    n_classfns;
	const char *type_lit;   /* `[Net.WebClient]::new()`, `[Convert]::FromBase64String(..)`: a type written in square brackets is the qualifier (powershell: "[") */
	const char *ctl_row;    /* a read of a server control's text (`txtArg.Text`) is the request: the row it is told as ("Request.Form") */
	const char *const *ctl_members; /* the members that read one: Text, Value */
	const char *req_obj;    /* the request object read through an index or a call, `Request["x"]`, `Request("x")`: it is the row `req_row` ("Request.Item") */
	const char *req_row;
	/* ---- a command line: sh, batch, powershell, tcl (diag_text_cmd.c) ---- */
	uint8_t     cmd;        /* 1: the first word of a segment is a call and the rest are its arguments; a "(" is an expression's bracket and a line break inside it ends nothing
				 * (powershell). 2: a "(" "[" "{" begins a command too, and a line break inside one ends a command (sh, batch, tcl) */
	const char *cmd_ends;   /* the bytes that end a segment and begin the next: ";&|(){}" for a shell, with "=" for powershell */
	const char *cmd_start;  /* the bytes besides letters, digits and "_" a word may begin with ("-/.~" in sh: options and paths) */
	const char *cmd_bytes;  /* and the ones it may hold ("-/.~:%+,@" in sh, with "\\" in batch and powershell) */
	const char *cmd_opt;    /* the bytes an option begins with ("-" in sh, "/" in batch): skipped after a word that hands the command on */
	const char *cmd_pass;   /* the bytes in front of a command that are no part of it: "@" in batch, "!" and "$" in sh, "&" and "." in powershell (the call operator) */
	const char *const *cmd_lead;    /* the words after which the command is the next word: sudo nohup exec time env xargs command setsid busybox, then do else if */
	const char *const *cmd_rearm;   /* words that begin a command wherever they stand: batch's `do` and `else`, which follow a ")" */
	const char *const *cmd_exts;    /* what is dropped from a command's name: ".exe" ".com" ".bat" ".cmd" */
	const char *const *cmd_sub;     /* tcl: the commands whose subcommand is part of the name ("file", "binary", "zlib", "interp"): `file delete` is "file.delete" */
	const char *const *cmd_paths;   /* the paths that are a row wherever a word begins with them: "/dev/tcp", "/dev/udp" (bash's sockets) */
	const struct kgenome_dtx_cond *cond;    /* batch: the condition of an `if` is skipped to find the command that follows it */
	uint8_t     cmd_assign; /* `name=value` at the head of a command is an assignment whose value is the word it touches (sh) */
	uint8_t     cmd_var;    /* a variable at the head of a command is the command (sh `$cmd args`); without it, only after a pass byte (powershell `& $x`) */
	uint8_t     cmd_ns;     /* tcl: "::" between the pieces of a command's name is "." in the table */
	const char *tag_calls;  /* cfml: a tag `<cfexecute ..>` that is a row is a call without a bracket; its attributes are its arguments. The tag opener ("<cf") */
	/* ---- scopes ---- */
	/* A COMMAND LANGUAGE's values (sh, batch, tcl): no expression is read - a value is a word (textual.h, "THE WORDS OF A COMMAND LANGUAGE") - and diag_text_cmdval.c answers the constants
	 * instead of the walk: the right side of every assignment and every word that holds an operation. `cmd_strip` says a command substitution takes the trailing line breaks off its
	 * output (the shell's), `cmd_split` that an expansion outside quotes is split into words and globbed (the shell's: only a value that is one plain word may be one).
	 * `cmd_vals` is the same for the three. */
	uint8_t     cmd_vals;
	uint8_t     cmd_strip;
	uint8_t     cmd_split;
	uint8_t     reads_view; /* the route also reads the normalised view of a script (its textual form with the typing taken out), and not only the script. Only
				 * php, whose view carries what the evaluator computed (the constants written where they were made) and so has names the file does
				 * not; for the others the view is the same program (CLAUDE.md: a derived object is not re-analysed), and reading it costs a second
				 * route run for nothing - measured on 300 js files, the symbol-block run on the views was half of the route's cost - and is wrong for
				 * python, whose form has no indentation left, so every function's variables merge (pdb.py's view reported create-call) */
	uint8_t     blocks;     /* enum kgenome_dtx_blocks */
	const char *fn_kw;      /* the word that begins a function: "function", "def", "sub" */
	uint8_t     fn_opaque;  /* `f = function () { ... }`: what is made inside the body is not a producer of f - f holds the function, not what its body
				 * computes. Every language but php: php's row keeps its old reading (the same defect, left so that its corpus lists do not move) */
	uint8_t     lexical;    /* a function sees the variables of the scope it is written in (js, python, lua, perl, java, c#); php's and ruby's `def` do not */
	uint8_t     fn_noparen; /* `sub name {`: a function may have no bracket for its parameters (perl) */
	const char *fn_kw2;     /* a second word that begins a function (vbscript `Sub` beside `Function`), closed by `End <that word>` (BLK_PAIR) */
	const char *arrow;      /* the arrow of a function written as an expression: js "=>", c# "=>", java "->" */
	uint8_t     shape;      /* a `name(...) {` whose name is not one of ctl_words is a function too (java, c#, js methods) */
	const char *const *ctl_words;   /* words that take a bracket and a block and are no function: if, for, while, switch, catch */
	const char *const *blk_open;    /* BLK_END: the words that open a block closed by `end` */
	const char *const *blk_open_first;      /* of them, the ones that open one only as the first word of a line (ruby's modifier `if`) */
	const char *blk_close;
	const char *global_kw;  /* `global a, b`: the names are the top level's (php, python) */
	const char *local_kw;   /* `Dim a, b`: the names are the function's own (vbscript) */
	uint8_t     global_default; /* a name that is no parameter and was not declared local is the top level's, read or assigned (vbscript: an undeclared name is a global) */
	/* ---- what a function gives back, and what an object is given (the summaries, diag_text_sum.c) ---- */
	const char *ret_kw;     /* the word that returns a value: "return" */
	uint8_t     ret_name;   /* a function is also a variable of its own name (vbscript): assigned inside it, the name returns (`getOutput = x`), and read anywhere it calls the function with no argument */
	const char *use_kw;     /* `function () use ($a)`: the closure's variables are its enclosing scope's (php) */
	/* ---- php's own: the request poured into variables, and variables named by a value ---- */
	uint8_t     dyn_var;    /* `$$k = `, `${expr} = `, extract(): a variable whose name is a value, and `$GLOBALS['n']` is `$n` */
	/* ---- call semantics ---- */
	const struct kgenome_dtx_callsem *callsem;
	uint32_t    n_callsem;
	const struct kgenome_dtx_pathsem *pathsem;
	uint32_t    n_pathsem;
};

/* The stages the relation layer runs for a language (diag_text_stages.c). */
unsigned kgenome_dtx_stages(uint32_t lang);

/* THE ONE HASH AND THE ONE COMPARISON of a name in this route's tables (variables, the cmdval reader's variables, the functions of a text, the paths nodes hold): the same bytes, or - where
 * `fold` - the same letters whatever their case (ASCII, as the lexer's rows are). The hash is SEEDED per text (`seed` is struct kgenome_dtx.seed, see diag_oatab.h): a file chooses
 * its names and must not choose which of them share a slot. */
static inline uint32_t kgenome_dtx_name_hash(uint64_t seed, const uint8_t *p, uint32_t n, int fold)
{
	uint64_t h = seed ^ (uint64_t)n;

	while (n--) {
		uint8_t c = *p++;

		h = kgenome_oatab_step(h, fold ? kof_lower_byte(c) : c);
	}
	return kgenome_oatab_fold(h);
}

static inline int kgenome_dtx_name_eq(const uint8_t *a, const uint8_t *b, uint32_t n, int fold)
{
	while (n--) {
		uint8_t x = *a++, y = *b++;

		if (fold) {
			x = kof_lower_byte(x);
			y = kof_lower_byte(y);
		}
		if (x != y)
			return 0;
	}
	return 1;
}

/* Does a line end at byte `i` of a text of `n`: a LF, or a CR that no LF follows (CRLF is ended by its LF; old Mac text, and a script written with CR alone, ends a line with the CR) (G13). */
static inline int kgenome_dtx_eol(const uint8_t *in, uint32_t n, uint32_t i)
{
	return in[i] == '\n' || (in[i] == '\r' && (i + 1u >= n || in[i + 1u] != '\n'));
}

/* Every producer a variable holds, nodes first and then slots: `k` below kgenome_dtx_var_nprod. */
static inline uint32_t kgenome_dtx_var_nprod(const struct kgenome_dtx_var *v)
{
	return (uint32_t)v->n_def + v->n_pdef;
}

static inline uint32_t kgenome_dtx_var_prod(const struct kgenome_dtx_var *v, uint32_t k)
{
	return k < v->n_def ? v->def[k] : v->pdef[k - v->n_def];
}

/* The row of a language, NULL when the route does not serve it. */
const struct kgenome_dtx_lang *kgenome_dtx_lang_find(uint32_t id);
/* One row per file: the rows themselves. */
extern const struct kgenome_dtx_lang kgenome_dtx_lang_php, kgenome_dtx_lang_js, kgenome_dtx_lang_py, kgenome_dtx_lang_perl,
	kgenome_dtx_lang_ruby, kgenome_dtx_lang_lua, kgenome_dtx_lang_jsp, kgenome_dtx_lang_aspx, kgenome_dtx_lang_vbs, kgenome_dtx_lang_asp,
	kgenome_dtx_lang_sh, kgenome_dtx_lang_bat, kgenome_dtx_lang_psh, kgenome_dtx_lang_tcl, kgenome_dtx_lang_cfml;

/* Is this word (n bytes, as written) in the list: case apart when `fold`. */
int kgenome_dtx_word_in(const char *const *list, const uint8_t *p, uint32_t n, int fold);

struct kgenome_dtx {
	const struct kgenome_dtx_lang *lang;
	unsigned       stages;  /* KGENOME_DTX_ST_*: what the table says this language uses */
	uint8_t        ret_len; /* the length of the row's `return` word, 0 when it has none: the walk asks it of every name */
	struct kgenome_dtx_sum *sum;    /* the functions of the text, when the stage is on and there is one (diag_text_sum.c) */
	struct kgenome_dtx_cv *cv;              /* the command reader, once made (kgenome_dtx_cv_get) */
	uint8_t        cv_tried;
	struct kgenome_dtx_ident *ident;        /* the node -> token map and the paths nodes hold, when the stage is on (diag_text_ident.c) */
	struct kgenome_diag_scan *s;
	uint32_t       n_in;    /* the text's size */
	int            depth;   /* the sink's count of unclosed "(" and "[": a line break inside one ends nothing */
	int           *dstk;    /* the count a "{" interrupted, given back by its "}": as deep as the text nests (it was 64 and the count of the ones past it was not given back), charged to the scan */
	uint32_t       nds, cdstk;
	uint32_t       lsa, lss;        /* the last line start asked for (diag_text_scope.c): the offset asked, and where its line begins */
	uint8_t        kwfirst[32];     /* the bytes the row's keywords begin with (a bit each, both cases when it folds): most names are none */
	uint8_t        kwmin, kwmax;    /* and the lengths they have */
	uint8_t        cmdfirst[32];    /* the bytes the row's command openers (`cmd_str`) begin with: a string that begins with one is read */
	uint8_t        jlast[32];       /* the bytes the row's joins end with: what in front of a name is no join, is told by one test */
	struct kgenome_dtx_capc *capc;  /* the memo of kgenome_dtx_cap: KGENOME_DTX_CAPC slots, made on the first lookup and charged */
	const uint8_t *in;
	struct kgenome_dtx_tok *t;
	uint32_t       nt, cap;
	int            oom;
	int32_t       *site;    /* the node a token made, -1 */
	int32_t       *match;   /* the bracket that closes (or opens) a token's bracket, -1 */
	struct kgenome_dtx_seg *seg;    /* the pieces of every variable's value (struct kgenome_dtx_seg): one arena, grown with the text */
	uint32_t       nsegs, csegs;
	struct kgenome_dtx_var **vt;     /* open addressing, over variables that never move (kgenome_dtx_vchunk) */
	struct kgenome_dtx_vchunk *vchunk;
	uint32_t       vcap, vn;
	uint32_t      *scope;   /* per token: the function body it is in (0: none) - one pass, kgenome_dtx_scopes */
	uint32_t       nscope;
	uint32_t      *sparent; /* per scope: the scope it is written in (only for a language whose row says `lexical`) */
	struct kgenome_dtx_alias *al;
	uint32_t      *alt;     /* open addressing over (scope, name): index + 1 of the NEWEST alias of that key, 0 an empty slot */
	uint32_t       altcap, nalt;    /* its slots, and the keys in it */
	uint32_t       nal, cal;
	uint32_t       shift;   /* where the text being lexed begins in `in`: a string's code is lexed again, from the middle of the text (diag_text_interp.c) */
	uint32_t       nest;    /* how many of those are open */
	uint32_t       steps;   /* work the evaluator has spent */
	uint64_t       seed;    /* the seed of this text's name hashes (kgenome_oatab_seed): made when the text is opened */
	uint64_t       listed;  /* tokens the scope pass read for `global` and `Dim` lists (kgenome_diag_text_work) */
	uint64_t       probes;  /* slots the open-addressing lookups and rehashes of this text looked at (told through kgenome_diag_text_work: the cost a test asserts) */
	uint32_t       shapes;  /* the shapes of row the language's function table has (kgenome_textual_fn_shapes): a method, an operator, a cast is looked for only where there is one */
	uint8_t        n_ops, n_casts, n_sufs;  /* the rows of those shapes, by index in the table (below): looked up once for the text and not at every token */
	uint8_t        op_row[16], cast_row[8], suf_row[8];
	uint8_t        list_ok;         /* a list is read where a join can take it (an argument of a join, the operand of a unary -join): other brackets are not parsed for their elements */
	uint8_t        in_call;         /* arguments open in the evaluator's recursion: a call's answer that is more than one value (lua's gsub) is taken as one only outside them */
	int            ev_depth; /* variables being evaluated, one inside another: `$a = $a . "x"` must stop (ev_stack holds them, so a cycle is told from a chain that is too deep) */
	const struct kgenome_dtx_var *ev_stack[32];
	uint16_t       ev_nest;  /* expressions open in the evaluator's recursion (ev_expr), bounded by EV_NEST: the program chooses how deep it nests */
	void         (*on_node)(void *user, const char *name);   /* told each node's table name, or NULL */
	void          *user;
	kgenome_textual_apply_fn apply;   /* what a call on constants does; NULL: no call is followed */
	void          *apply_user;
	struct kgenome_dtx_layers *lay;
	/*
	 * EVERY VARIABLE OF A SCOPE, once the request has been poured into its variables: `extract($_REQUEST)` makes $ctime and $atime of what the
	 * sender called them - and overwrites a variable the program had set, which is what extract does by default - and so does
	 * `foreach ($_POST as $k => $v) $$k = $v;`. `extract_src` is the request node that went in (-1 none) and `extract_scope` the scope it
	 * was done in; a variable read in that scope has it among its producers (and is no constant). `vdyn` collects the right side of an
	 * assignment to a variable whose NAME is not constant.
	 */
	int32_t        extract_src;
	uint32_t       extract_scope;
	struct kgenome_dtx_var vdyn;
	/* While the constants are asked for (on_const) of a TYPED language the evaluator follows a variable only where its value cannot depend on the order
	 * the program runs in: a variable of the top level, assigned exactly once and never appended to. The evaluator keeps no control flow, so a
	 * variable assigned in two places is "the last one" to it and a parameter is no assignment at all - fine for finding a name, wrong for a value that is
	 * written into the text (python's `new = new + b' '` came out `new = ' '`). */
	uint8_t        strict;
	void         (*on_const)(void *user, uint64_t off, uint64_t len, const uint8_t *value, uint32_t n);
	void         (*on_head)(void *user, uint64_t off, uint64_t len, const uint8_t *value, uint32_t n);
	void          *const_user;
	struct kgenome_dtx_cand *cand;  /* only for layer 0, and only when on_const is set */
	uint32_t       ncand, ccand;
	/* THE ROW OF A CALL THAT A VALUE NAMED: `$l = 'create_function'; $l('', $c)` makes a node of the name `$l` comes to, and its bracket is read by that name's row (which argument it
	 * acts on, which it writes) as the bracket of `create_function(` is. `named_node` is the node the row is for (-1 none), set where the node is made and read where its "(" is. */
	int32_t        named_node;
	const struct kgenome_dtx_callsem *named_cs;
	uint8_t        saw_decoder;     /* the evaluation just made called a decoder: the decode hook owns what a decoder makes, and is not told twice */
	uint32_t       step_cap;        /* work the evaluator may spend on this text: it grows with the text, a fixed number would drop the late ones */
	uint32_t       layer;   /* 0 for the file, 1.. for code it computes */
	uint64_t       layer_at; /* where a node of a layer is told to be: the call that ran the layer, in the file */
};

int kgenome_dtx_charge(struct kgenome_dtx *x, uint64_t n);
/* A bound of the route fired and evidence was left unread or unlinked: the scan's status says so (KGENOME_TRUNCATED). The one way every such bound of this route reports (rule 4); the macro
 * carries the place, so that a DEBUG build prints one "[cut] file:line" for it, as kgenome_diag_note does. */
void kgenome_dtx_cut_at(struct kgenome_dtx *x, const char *file, int line);
#define kgenome_dtx_cut(x) kgenome_dtx_cut_at((x), __FILE__, __LINE__)
/* Make room in a table that grows with the text: `*p` holds `*cap` elements of `elem` bytes and is given room for `need` (the capacity doubles from 32), charged to the scan; the new part is NOT cleared.
 * 0 when the ledger or memory refuses (said, and the route stops). */
int kgenome_dtx_grow(struct kgenome_dtx *x, void **p, uint32_t *cap, uint32_t need, size_t elem);
/* Make room for one more entry in an open-addressing table (diag_oatab.h): `*tab` holds `*cap` slots of `elem` bytes (an empty slot is all zero) and `n` entries; past half full it is doubled
 * (`first` slots when it has none), charged to the scan, and the entries moved by `hash` (called with `x`). 1 when there is room; 0 when the ledger or memory refuses (said, and the route stops). */
int kgenome_dtx_oa_grow(struct kgenome_dtx *x, void **tab, uint32_t *cap, uint32_t n, uint32_t first, size_t elem, kgenome_oatab_hash_fn hash);

/* The words of the commands of a command language, read as its constants are (diag_text_cmdval.c): the reader kept open (the variables collected once) and the values of the words of the command that begins at byte `off`, word 0 the command itself;
 * a word that is not a constant has p == NULL, and `at` says where each is written. The words are the caller's to free. */
struct kgenome_dtx_val;
struct kgenome_dtx_cv;
/* The shell/batch/tcl command reader kept open for the scan: made once, at the first stage that asks (the path stage for a command that needs the variables, or the constants of a command language),
 * so that the variables are collected and counted ONCE per text however many stages read them. NULL for a language with no command words. Freed with the scan (kgenome_dtx_close). */
struct kgenome_dtx_cv *kgenome_dtx_cv_get(struct kgenome_dtx *x);
uint32_t kgenome_dtx_cv_command(struct kgenome_dtx_cv *w, uint32_t off, struct kgenome_dtx_val *out, uint32_t *at, uint32_t max);
void kgenome_dtx_cv_free(struct kgenome_dtx_cv *w);

/* The constants of a command language (sh, batch, tcl): see diag_text_cmdval.c. */
void kgenome_dtx_cmd_consts(struct kgenome_dtx *x);

/* ---- the walk and what the route (diag_text_route.c) asks of it ---- */
int kgenome_dtx_sink(void *u, const struct kgenome_textual_span *sp);     /* the lexer's sink: spans into tokens */
/* A string span at byte `off` of the text: one 'S' token, or - where the row says it runs a command or interpolates - the tokens of the code it holds (diag_text_interp.c). */
int kgenome_dtx_sink_str(struct kgenome_dtx *x, const struct kgenome_textual_span *sp, uint32_t off);
/* A tag span of a page language whose tags are calls (cfml): it ends the statement before it, and a tag that is a row gives a 'g' token. */
int kgenome_dtx_sink_tag(struct kgenome_dtx *x, const struct kgenome_textual_span *sp, uint32_t off);
/* An end of statement 'T' at byte `off`, where there is a statement to end. */
int kgenome_dtx_push_term(struct kgenome_dtx *x, uint32_t off);
/* A token pushed: its place in the text, its length, its kind (see struct kgenome_dtx_tok). 0 when the scan is full. */
int kgenome_dtx_push(struct kgenome_dtx *x, uint32_t off, uint32_t len, uint8_t k, uint8_t open, uint8_t close, uint8_t fl);
/* Is `c` a byte of a name in the row's language. */
int kgenome_dtx_identc(const struct kgenome_dtx *x, uint8_t c);
void kgenome_dtx_walk(struct kgenome_dtx *x);
void kgenome_dtx_cand_add(struct kgenome_dtx *x, uint32_t rs, uint32_t re);
void kgenome_dtx_vars_free(struct kgenome_dtx *x);
/* One lexed text, walked: the file (layer 0) or a layer of code it computes; `hooks` carries the callbacks and the language, which a layer inherits. */
void kgenome_dtx_run_one(struct kgenome_diag_scan *s, const uint8_t *base, uint64_t size, uint32_t flags, const struct kgenome_dtx *hooks,
			 struct kgenome_dtx_layers *lay, uint32_t layer, uint64_t layer_at);

/* ---- names (diag_text_lang.c) ---- */
/* The row of a name the route told: the language's own table, then those its objects are rows of. 0 for none; `target` gets the table. */
uint16_t kgenome_dtx_name_row(const struct kgenome_dtx_lang *l, const char *name, unsigned *target, uint16_t *cap);
void kgenome_dtx_prefilters(struct kgenome_dtx *x);
/* The capability the language's table gives the name `p`/`n`, KGENOME_NUCLEO_NONE when it has none or the name does not fit (refused, never cut).
 * `spelled`, when not NULL, gets the table's spelling of it. */
uint16_t kgenome_dtx_cap(struct kgenome_dtx *x, const uint8_t *p, uint32_t n, const char **spelled);
/* The same in another language's table: the row is looked up there, not memoised (it is rare), and refused when it does not fit just as well. */
uint16_t kgenome_dtx_cap_in(struct kgenome_dtx *x, unsigned target, const uint8_t *p, uint32_t n);
/* Is token `i` the word `w` (lower case): by the language's fold. */
int kgenome_dtx_is_word(const struct kgenome_dtx *x, uint32_t i, const char *w);

/* ---- qualified names (diag_text_chain.c) ---- */
/* How many tokens of a join (".", "::", "->") end just before token `i`, or begin at it; 0 for none. */
uint32_t kgenome_dtx_join_before(const struct kgenome_dtx *x, uint32_t i);
uint32_t kgenome_dtx_join_after(const struct kgenome_dtx *x, uint32_t i);
/* Is token `i` the member of something in front of it (what a join precedes). */
int kgenome_dtx_member(const struct kgenome_dtx *x, uint32_t i);
/*
 * THE NAME OF THE CALL whose name token is `i`, as its table spells a qualified name ("os.system", "Runtime.exec"): the pieces of the chain
 * in front of it joined with ".", a receiver that is itself a call dropped (`Runtime.getRuntime().exec(c)` is "Runtime.exec"; `new File(p).delete()`
 * keeps the constructor, "File.delete"), and a variable at the root that holds an object replaced by its class (`s = socket.socket()` makes
 * `s.connect(...)` "socket.socket.connect"; `cp = require('child_process')` makes `cp.exec` "child_process.exec"). Its length, 0 when the chain
 * has no name (a call on a value, a subscript, a name that does not fit): then it is not looked up. `root` gets the chain's first token.
 */
uint32_t kgenome_dtx_chain_name(struct kgenome_dtx *x, uint32_t i, char *b, uint32_t cap, uint32_t *root);
/*
 * The same, and what else the chain said (struct kgenome_dtx_chain_res): `root` is the chain's first token, `target` the table the name is a row of (0: the language's
 * own; a COM object is a row of the VBS table, whatever language made it) and `flags` KGENOME_NUCLEO_F_BUILT when the class the name begins with was made by the program
 * (`CreateObject("WScr" & "ipt.Shell")`).
 */
struct kgenome_dtx_chain_res {
	uint32_t root;
	unsigned target;
	uint16_t flags;
	uint8_t  drop;          /* the name is looked up without its leading pieces (a java class of cfml) */
};
uint32_t kgenome_dtx_chain_full(struct kgenome_dtx *x, uint32_t i, char *b, uint32_t cap, struct kgenome_dtx_chain_res *r, uint32_t depth);
/* The capability of the chain's name `b` (`len` bytes) in table `r->target` (0: the language's own): the whole name, then - where the row's `ns_drop` says - without its leading pieces; `off` is where the name that matched begins. */
uint16_t kgenome_dtx_chain_cap(struct kgenome_dtx *x, const struct kgenome_dtx_chain_res *r, const char *b, uint32_t len, uint32_t *off);
/* ---- objects of a class a call names (diag_text_class.c) ---- */
int kgenome_dtx_may_make_object(const struct kgenome_dtx *x, uint32_t f);
const struct kgenome_dtx_classfn *kgenome_dtx_classfn_named(const struct kgenome_dtx *x, const char *name, uint32_t n, int bare);
/* The class of the object the call named `callee` (as chain_full spells it) makes, whose "(" is token `open`: written in `b`, its length, 0 when it is no such call. */
uint32_t kgenome_dtx_class_call(struct kgenome_dtx *x, const char *callee, uint32_t clen, uint32_t open, char *b, uint32_t cap, struct kgenome_dtx_chain_res *r);
/* The same for a command (`New-Object -ComObject X`) in tokens [from, to), and for the group `(New-Object X)` whose "(" is token `o`. */
uint32_t kgenome_dtx_class_command(struct kgenome_dtx *x, uint32_t from, uint32_t to, char *b, uint32_t cap, struct kgenome_dtx_chain_res *r);
uint32_t kgenome_dtx_class_group(struct kgenome_dtx *x, uint32_t o, char *b, uint32_t cap, struct kgenome_dtx_chain_res *r);
/* A type literal `[A.B]` whose "]" is token `k`: its bytes and length, NULL when it is not one. */
const uint8_t *kgenome_dtx_type_lit(const struct kgenome_dtx *x, uint32_t k, uint32_t *n);

/* The token that ends the request member beginning at token `i` ("request.args", "$ENV{QUERY_STRING}"), or -1 when the chain from `i` is none; `b` (`cap` bytes) gets its name. */
int32_t kgenome_dtx_request_end(struct kgenome_dtx *x, uint32_t i, char *b, uint32_t cap);
/* The length of the append operator (".=", "+=") spelled by the tokens from `i`, 0 when it is not there. */
uint32_t kgenome_dtx_append_len(const struct kgenome_dtx *x, uint32_t i);
/* `new X(...)` at name token `i`, followed by `.m(...)`: the token of the call the construction is the receiver of, or 0. */
uint32_t kgenome_dtx_ctor_final(const struct kgenome_dtx *x, uint32_t i);

/* ---- scopes (diag_text_scope.c) ---- */
int kgenome_dtx_scopes(struct kgenome_dtx *x);
/* ---- the paths nodes name (diag_text_ident.c) ---- */
/* Node `node` was made at token `tok`: kept, for the pass that runs when the walk is over. */
void kgenome_dtx_ident_note(struct kgenome_dtx *x, int32_t node, uint32_t tok);
/* The pass: two nodes that hold the same constant path (a node that makes the file first) are linked, shared. */
void kgenome_dtx_ident(struct kgenome_dtx *x);
void kgenome_dtx_ident_free(struct kgenome_dtx *x);
/* ---- the functions a text defines (diag_text_sum.c) ---- */
/* The table, made when the scope pass has counted a function; freed with the text. 0 when it could not be made. */
int kgenome_dtx_sum_new(struct kgenome_dtx *x);
void kgenome_dtx_sum_free(struct kgenome_dtx *x);
/* Function `id` (its scope id) was found: `kw` is its keyword (or the "{" of a method written `name(...) {`), `par` the "(" of its parameter list (0 none), `from` the first token of an arrow's parameters, `depth` the functions it is written inside. */
int kgenome_dtx_sum_fn(struct kgenome_dtx *x, uint32_t id, uint32_t kw, uint32_t par, uint32_t from, uint32_t depth);
/* The slot of the parameter declared at token `tok`, 0 when it declares none. */
uint32_t kgenome_dtx_sum_param(const struct kgenome_dtx *x, uint32_t tok);
/* The functions a call whose "(" is token `open` names: the first of the name (the others follow it), 0 when it calls none the text defines. */
uint32_t kgenome_dtx_sum_callee(struct kgenome_dtx *x, uint32_t open);
/* The functions a name read on its own calls (a language whose functions are variables of their own name), the first of the name; 0 for none. */
uint32_t kgenome_dtx_sum_bare_callee(struct kgenome_dtx *x, uint32_t tok);
/* Is variable token `i` the name of the function it is written in (a language that returns by assigning its own name). */
int kgenome_dtx_sum_own_name(const struct kgenome_dtx *x, uint32_t i);
/* A value went into argument `arg` of a call of `head` written in scope `cs`: the producers are the node (-1 none) and the variable's. */
void kgenome_dtx_sum_arg(struct kgenome_dtx *x, uint32_t head, uint32_t cs, uint32_t arg, int32_t node, const struct kgenome_dtx_var *v);
/* A value was returned by function `fn` (its scope id). */
void kgenome_dtx_sum_ret(struct kgenome_dtx *x, uint32_t fn, int32_t node, const struct kgenome_dtx_var *v);
uint32_t kgenome_dtx_sum_ret_slot(const struct kgenome_dtx *x, uint32_t fn);
/* Is argument `arg` of the call of `head` (written in scope `cs`) held by a parameter of every function of the name: the call's result then carries it only through the return. */
int kgenome_dtx_sum_bound(struct kgenome_dtx *x, uint32_t head, uint32_t cs, uint32_t arg);
/* A link from slot `pseudo` into node `to` is kept until the whole text is read. */
void kgenome_dtx_sum_pend(struct kgenome_dtx *x, uint32_t pseudo, uint32_t to, uint8_t role);
/* The walk is over: every pending link, made from the producers its slot reaches. */
void kgenome_dtx_sum_resolve(struct kgenome_dtx *x);
static inline int kgenome_dtx_is_p(const struct kgenome_dtx *x, uint32_t i, char c)
{
	return i < x->nt && x->t[i].k == 'P' && x->in[x->t[i].off] == (uint8_t)c;
}
/* Does a statement end at token `i`: a ";", or the 'T' a line break or the end of an island made. */
int kgenome_dtx_is_term(const struct kgenome_dtx *x, uint32_t i);
/*
 * THE VARIABLE A "$" TOKEN IS, in the scope the token is in: `used` is how many tokens it took (kgenome_dtx_var_key), 0 for a token
 * that is not a variable. NULL with `make` clear when nothing was ever assigned to it.
 */
struct kgenome_dtx_var *kgenome_dtx_var_for(struct kgenome_dtx *x, uint32_t tok, uint32_t *used, int make);

/* The piece of a variable's value that follows `s` (the first when `s` is NULL), NULL after the last. */
static inline const struct kgenome_dtx_seg *kgenome_dtx_seg_next(const struct kgenome_dtx *x, const struct kgenome_dtx_var *v, const struct kgenome_dtx_seg *s)
{
	uint32_t i = s ? s->next : v->seg_head;

	return i ? &x->seg[i - 1u] : NULL;
}
/* Add the right side [rs, re) to variable `v`'s pieces. 0 when the arena was refused room (said). */
int kgenome_dtx_seg_add(struct kgenome_dtx *x, struct kgenome_dtx_var *v, uint32_t rs, uint32_t re);
/* `v` holds no piece: a plain assignment replaces what it held. */
void kgenome_dtx_seg_clear(struct kgenome_dtx_var *v);

/* A producer (a node, or a summary's slot) flowed into variable `v`: its latest few are kept, nodes and slots apart (diag_text_vars.c). The oldest one a full list pushes out is evidence
 * lost - the variable is marked (`lost`) and a read of it is said (kgenome_dtx_cut), so that a variable nothing reads costs no report, and one that is read with less than it was given does. */
void kgenome_dtx_var_def(struct kgenome_dtx_var *v, uint32_t node);

/*
 * THE VARIABLE A "$" TOKEN NAMES. `$name` is `name`; `$GLOBALS['name']` is the global variable `name` - the same variable, which
 * is why a script that hides its function names in the array is hiding them in plain sight. Answers how many tokens it took
 * (1, or 4 for the array form), 0 for a token that is not a variable.
 */
uint32_t kgenome_dtx_var_key(const struct kgenome_dtx *x, uint32_t i, const uint8_t **name, uint32_t *len);

/* The tokens of argument `val` of the call whose "(" is token `open`, as [*rs, *re). 0 when the call has no such argument. */
int kgenome_dtx_arg_range(const struct kgenome_dtx *x, uint32_t open, uint32_t val, uint32_t *rs, uint32_t *re);

/* A constant string made by the evaluator: `p` is malloc'ed, `n` bytes. */
struct kgenome_dtx_val {
	uint8_t *p;
	uint32_t n, cap;
	/* The value is a STRING by the program's own typing: a literal, or a call's answer, was part of it. Not one that is only digits, a number
	 * the program wrote (`(5)`, `1 + 2`): written back as a literal it would be another value in a language that keeps the two apart. */
	uint8_t  str;
};

/*
 * WHAT A VARIABLE, OR A CALLEE WRITTEN AS AN ARRAY READ, IS - as a constant string, when the program says so and the evaluator
 * can follow it: literals (their value, escapes applied), ".", other variables, and the pure functions a script uses to
 * hide a name (str_replace, strtr, strrev, str_rot13, strtolower/upper, ucfirst, substr, chr, base64_decode, hex2bin,
 * urldecode, trim). 1 and `out` filled, or 0 (and `out` freed) for "not constant". `*built` is set when the value is not just
 * one literal as written: the name was MADE.
 */
int kgenome_dtx_eval_var(struct kgenome_dtx *x, const struct kgenome_dtx_var *v, struct kgenome_dtx_val *out, int *built);
/* The same for the tokens [rs, re) taken as one expression - an argument of a call. 1 only when all of them were followed. */
int kgenome_dtx_eval_range(struct kgenome_dtx *x, uint32_t rs, uint32_t re, struct kgenome_dtx_val *out, int *built);
/* The callee of `$a[expr](`, `lb` being the "[" token: element `expr` of the array literal `$a` holds. */
int kgenome_dtx_eval_element(struct kgenome_dtx *x, uint32_t lb, struct kgenome_dtx_val *out, int *built);
void kgenome_dtx_val_free(struct kgenome_dtx_val *v);

#endif /* KGENOME_DIAG_TEXT_PRIVATE_H */
