#ifndef KGENOME_TEST_TEXTUAL_JS_STMT_H
#define KGENOME_TEST_TEXTUAL_JS_STMT_H

/*
 * textual_js_stmt.h - the statements of the generator of javascript programs (textual_js_gen.h has the
 * tokens and expressions): declarations, if, loops, try, switch, labels, functions and classes, the
 * ";" or line break that ends each, and `program()`.
 */

/* ---- statements ----------------------------------------------------------------------- */

static void block(struct gen *g, uint32_t depth)
{
	put_code(g, "{");
	stmts(g, depth, 1u + rnd(g, 3));
	put_code(g, "}");
	g->unterminated = 0;
}

/* The statement of an if, a loop: one that needs no declaration, ended by ";" when it is a leaf. */
static int stmt(struct gen *g, uint32_t depth, int simple, int safe);

static void body_stmt(struct gen *g, uint32_t depth)
{
	if (stmt(g, depth, 1, 0))
		put_code(g, ";");
	g->unterminated = 0;
}

static void new_name(struct gen *g, const char *pre, char *out, size_t cap)
{
	snprintf(out, cap, "%s%u", pre, g->uniq++);
}

static void class_decl(struct gen *g, uint32_t depth)
{
	char nm[24], mn[24];
	uint32_t n = rnd(g, 4), k;

	uint8_t strict = g->strict;

	new_name(g, "C", nm, sizeof nm);
	g->strict = 1;
	put_code(g, "class");
	sep(g, 1, 1);
	put_code(g, nm);
	if (rnd(g, 3) == 0) {
		sep(g, 1, 1);
		put_code(g, "extends");
		sep(g, 1, 1);
		put_code(g, "Base");
	}
	sep(g, 1, 0);
	put_code(g, "{");
	for (k = 0; k < n && room(g); k++) {
		uint32_t r = rnd(g, 8);

		sep(g, 1, 0);
		if (r < 2) {
			if (rnd(g, 2)) {
				put_code(g, "static");
				sep(g, 1, 1);
			}
			put_code(g, "m");
			params(g);
			sep(g, 1, 0);
			body(g, depth, 0, 0);
		} else if (r < 3) {
			int is_set = rnd(g, 2) == 0;

			put_code(g, is_set ? "set" : "get");
			sep(g, 1, 1);
			put_code(g, "acc");
			put_code(g, is_set ? "(v)" : "()");
			sep(g, 1, 0);
			body(g, depth, 0, 0);
		} else if (r < 4) {
			put_code(g, "async");
			sep(g, 0, 1);
			put_code(g, "am");
			params(g);
			sep(g, 1, 0);
			body(g, depth, 0, 1);
		} else if (r < 5) {
			put_code(g, "*gm");
			params(g);
			sep(g, 1, 0);
			body(g, depth, 1, 0);
		} else if (r < 6) {
			uint8_t as = g->asy, ge = g->gen;

			new_name(g, "#p", mn, sizeof mn);
			put_code(g, mn);
			sep(g, 1, 0);
			put_code(g, "=");
			sep(g, 1, 0);
			g->asy = g->gen = 0;
			expr(g, depth);
			g->asy = as; g->gen = ge;
			put_code(g, ";");
		} else if (r < 7) {
			uint8_t fn = g->fn, as = g->asy, ge = g->gen, lo = g->loop, br = g->brk;

			put_code(g, "static");
			sep(g, 1, 0);
			put_code(g, "{");
			g->fn = g->asy = g->gen = g->loop = g->brk = 0;
			stmts(g, depth, 1);
			g->fn = fn; g->asy = as; g->gen = ge; g->loop = lo; g->brk = br;
			put_code(g, "}");
		} else {
			put_code(g, "[");
			quoted(g);
			put_code(g, "]");
			params(g);
			sep(g, 1, 0);
			body(g, depth, 0, 0);
		}
	}
	sep(g, 1, 0);
	put_code(g, "}");
	g->strict = strict;
	g->unterminated = 0;
}

static void func_decl(struct gen *g, uint32_t depth)
{
	char nm[24];
	int is_gen = rnd(g, 4) == 0, is_asy = rnd(g, 4) == 0;

	new_name(g, "f", nm, sizeof nm);
	if (is_asy) {
		put_code(g, "async");
		sep(g, 0, 1);
	}
	put_code(g, "function");
	if (is_gen)
		put_code(g, "*");
	sep(g, 1, 1);
	put_code(g, nm);
	params(g);
	sep(g, 1, 0);
	body(g, depth, is_gen, is_asy);
	g->unterminated = 0;
}

/* A loop's body: `break` and `continue` mean something in it. */
static void loop_body(struct gen *g, uint32_t depth)
{
	uint8_t lo = g->loop, br = g->brk;

	g->loop = g->brk = 1;
	sep(g, 1, 0);
	body_stmt(g, depth);
	g->loop = lo; g->brk = br;
}

static void for_stmt(struct gen *g, uint32_t depth)
{
	char nm[24];
	uint32_t r = rnd(g, 5);

	put_code(g, "for");
	if (r == 4 && g->asy) {
		sep(g, 0, 1);
		put_code(g, "await");
	}
	sep(g, 1, 0);
	put_code(g, "(");
	sep(g, 1, 0);
	if (r == 0) {
		put_code(g, "var i = 0;");
		sep(g, 1, 0);
		put_code(g, "i < 3;");
		sep(g, 1, 0);
		put_code(g, "i++");
	} else if (r == 1) {
		put_code(g, ";;");
	} else {
		new_name(g, "k", nm, sizeof nm);
		put_code(g, r == 2 ? "var " : "const ");
		put_code(g, nm);
		sep(g, 1, 1);
		put_code(g, r == 2 ? "in" : "of");
		sep(g, 1, 1);
		expr(g, depth ? depth - 1u : 0u);
	}
	sep(g, 1, 0);
	put_code(g, ")");
	loop_body(g, depth);
}

/* Words after which a leaf statement may stop with no ";": the lexer's own cue is a line break. */
static int stmt(struct gen *g, uint32_t depth, int simple, int safe)
{
	static const char *const asg[] = { "=", "+=", "/=", "-=", "*=", "<<=", "||=", "&&=", "**=" };
	uint32_t r = rnd(g, 22);
	char nm[24];

	if (!depth || !room(g))
		r = r % 3 ? 2u : 0u;
	/* after a statement with no ";" only a statement that begins with a name or a keyword may follow */
	if (safe && (r == 1 || r == 2 || r == 20 || r == 21 || (r == 15 && !g->fn)))
		r = 18;
	if (simple && (r == 12 || r == 13))
		r = 2;
	switch (r) {
	case 0: {                       /* var, let, const, with a pattern sometimes */
		uint32_t k = rnd(g, 6);

		if (simple || k < 2) {
			put_code(g, "var");
			sep(g, 1, 1);
			put_code(g, "x");
		} else if (k < 4) {
			new_name(g, "v", nm, sizeof nm);
			put_code(g, k == 2 ? "let" : "const");
			sep(g, 1, 1);
			put_code(g, nm);
		} else {
			put_code(g, "var");
			sep(g, 1, 0);
			put_code(g, k == 4 ? "{ a, b: [c] }" : "[p, , ...q]");
		}
		sep(g, 1, 0);
		put_code(g, "=");
		sep(g, 1, 0);
		expr(g, depth);
		return 1;
	}
	case 1: case 2: case 20: case 21:
		expr_f(g, depth, F_STMT);
		return 1;
	case 3: case 4:
		put_code(g, "if");
		sep(g, 1, 0);
		put_code(g, "(");
		sep(g, 1, 0);
		expr(g, depth);
		sep(g, 1, 0);
		put_code(g, ")");
		sep(g, 1, 0);
		body_stmt(g, depth - 1u);
		if (rnd(g, 3) == 0) {
			sep(g, 1, 0);
			put_code(g, "else");
			sep(g, 1, 1);
			body_stmt(g, depth - 1u);
		}
		return 0;
	case 5:
		for_stmt(g, depth - 1u);
		return 0;
	case 6: case 7:
		put_code(g, "while");
		sep(g, 1, 0);
		put_code(g, "(");
		sep(g, 1, 0);
		expr(g, depth);
		sep(g, 1, 0);
		put_code(g, ")");
		loop_body(g, depth - 1u);
		return 0;
	case 8:
		put_code(g, "do");
		sep(g, 1, 1);
		{
			uint8_t lo = g->loop, br = g->brk;

			g->loop = g->brk = 1;
			body_stmt(g, depth - 1u);
			g->loop = lo; g->brk = br;
		}
		sep(g, 1, 0);
		put_code(g, "while");
		sep(g, 1, 0);
		put_code(g, "(");
		expr(g, depth - 1u);
		put_code(g, ")");
		put_code(g, ";");
		return 0;
	case 9:
		if (simple) {
			put_code(g, ";");
			return 0;
		}
		block(g, depth - 1u);
		return 0;
	case 10:                        /* try / catch / finally */
		put_code(g, "try");
		sep(g, 1, 0);
		block(g, depth - 1u);
		sep(g, 1, 0);
		if (rnd(g, 4)) {
			put_code(g, "catch");
			sep(g, 1, 0);
			if (rnd(g, 3)) {
				put_code(g, "(e)");
				sep(g, 1, 0);
			}
			block(g, depth - 1u);
			sep(g, 1, 0);
		}
		put_code(g, "finally");
		sep(g, 1, 0);
		block(g, depth - 1u);
		return 0;
	case 11: {                      /* switch */
		uint32_t n = 1u + rnd(g, 3), k;
		uint8_t br = g->brk;

		put_code(g, "switch");
		sep(g, 1, 0);
		paren_expr(g, depth - 1u);
		sep(g, 1, 0);
		put_code(g, "{");
		g->brk = 1;
		for (k = 0; k < n; k++) {
			sep(g, 1, 0);
			put_code(g, "case");
			sep(g, 1, 1);
			expr(g, depth - 1u);
			sep(g, 1, 0);
			put_code(g, ":");
			stmts(g, depth - 1u, 1);
		}
		sep(g, 1, 0);
		put_code(g, "default:");
		stmts(g, depth - 1u, 1);
		g->brk = br;
		sep(g, 1, 0);
		put_code(g, "}");
		return 0;
	}
	case 12: func_decl(g, depth - 1u); return 0;
	case 13: class_decl(g, depth - 1u); return 0;
	case 14:
		put_code(g, "throw");
		sep(g, 0, 1);
		expr(g, depth);
		return 1;
	case 15:
		if (g->fn) {
			put_code(g, "return");
			if (rnd(g, 4)) {
				sep(g, 0, 1);       /* no line terminator after `return` */
				expr(g, depth);
			}
			return 1;
		}
		expr_f(g, depth, F_STMT);
		return 1;
	case 16:
		if (g->loop)
			put_code(g, rnd(g, 2) ? "continue" : "break");
		else if (g->brk)
			put_code(g, "break");
		else
			put_code(g, "debugger");
		return 1;
	case 17: {                      /* a label, and a break out of it */
		char lb[24];

		new_name(g, "L", lb, sizeof lb);
		put_code(g, lb);
		put_code(g, ":");
		sep(g, 1, 0);
		put_code(g, "{");
		stmts(g, depth - 1u, 1);
		sep(g, 1, 0);
		put_code(g, "break");
		sep(g, 0, 1);
		put_code(g, lb);
		put_code(g, ";");
		put_code(g, "}");
		g->unterminated = 0;
		return 0;
	}
	default:                        /* `a = expr`, `a.b = expr`, `a(expr)`: begins with a name */
		put_code(g, "x");
		if (rnd(g, 3) == 0) {
			static const char *const prop[] = { "y", "return", "in" };

			put_code(g, ".");
			put_code(g, PICK(g, prop));
		}
		sep(g, 1, 0);
		if (rnd(g, 4) == 0) {
			callargs(g, depth);
		} else {
			put_code(g, PICK(g, asg));
			sep(g, 1, 0);
			expr(g, depth);
		}
		return 1;
	}
}

/* Statements, ended by ";" or by a line break where the next cannot continue them. */
static void stmts(struct gen *g, uint32_t depth, uint32_t n)
{
	static const char *const brk[] = { "\n", "\r\n", "\r", "\xe2\x80\xa8", "\xe2\x80\xa9", "\n\n   " };
	uint32_t i;

	for (i = 0; i < n && room(g); i++) {
		int leaf, last = i + 1u == n;

		sep(g, 1, 0);
		leaf = stmt(g, depth, 0, g->unterminated);
		if (!leaf) {
			g->unterminated = 0;
		} else if (last ? rnd(g, 3) == 0 : rnd(g, 4) == 0) {
			/* automatic semicolon: a line terminator, which also keeps what follows from running into it
			 * ("/a/g" and "break" are not "/a/gbreak") */
			if (rnd(g, 4) == 0) {
				/* a block comment that holds a line terminator ends the statement too: the form keeps it a line
				 * break, and a form that made it a gap would join two statements (V8 refuses the result) */
				static const char *const cmt[] = { "/*\n*/", "/* a \r\n b */", "/*\xe2\x80\xa8*/", "/*\r*/" };
				const char *c = PICK(g, cmt);

				put_lit(g, c, (uint32_t)strlen(c), G_COM, 2u, 2u, 0);
			} else {
				put_code(g, PICK(g, brk));
			}
			g->unterminated = 1;
		} else {
			put_code(g, ";");
			g->unterminated = 0;
		}
	}
}

static void program(struct gen *g, uint32_t seed)
{
	memset(g, 0, offsetof(struct gen, buf));
	g->rng = seed * 2654435761u + 0x1234567u;
	g->html = rnd(g, 6) == 0;
	g->uniq = 1;
	if (rnd(g, 8) == 0) {
		static const char hb[] = "#!/usr/bin/env node";

		put_lit(g, hb, sizeof hb - 1u, G_COM, 2u, 0, 0);
		put_code(g, "\n");
	} else if (rnd(g, 8) == 0) {
		put_code(g, "\xef\xbb\xbf");
	}
	stmts(g, 3u + rnd(g, GEN_DEPTH - 2u), 1u + rnd(g, 7));
}

#endif /* KGENOME_TEST_TEXTUAL_JS_STMT_H */
