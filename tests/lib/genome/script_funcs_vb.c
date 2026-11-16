/*
 * genome / script_funcs_vb - the VB function strategy (celllysis/script_funcs_vb.c) from CONSTRUCTED text only: VBScript (.vbs),
 * the VBScript of classic ASP pages (code in islands between markup) and VB.NET shapes, linked against libkgenome.a alone.
 *
 * WHAT IS ASSERTED: as in script_funcs_py.c (the kit is script_funcs_kit.h): exact (off, len,
 * name_off, name_len) and END_OPEN per entry, the properties of any answer, and the same entries under CRLF, lone CR and behind a
 * BOM. The ASP cases lex the page with the asp lexer and run this strategy on it, as the dispatcher will for an ASP page.
 *
 * WHY THE OLD TESTS MISSED IT: every group is (a) - the strategy was a stub (NO_TABLE). The groups that decide the END (Exit Sub,
 * End alone, End If, "End _" continued, a multi-line lambda's own End Sub, a body with no End: Declare, MustOverride, an interface
 * member, an auto-property) and the island group (a function that spans islands, markup between) are also (b): each is the one
 * statement that tells a closer from a statement that is not one.
 */

#include "hk.h"

#include <kgenome.h>
#include <celllysis/script_private.h>

#define SF_LANG  KGENOME_TEXTUAL_LANG_VBS
#define SF_STRAT kgenome_script_funcs_vb
#define SF_CR    1

#include "script_funcs_kit.h"

/* ---- VB ----------------------------------------------------------------------------------------------------------------- */

static void shapes(void)
{
	SF_CASE("sub", "Sub Foo()\n  x = 1\nEnd Sub\nFoo\n", { "Sub Foo", "End Sub", "Foo", 0 });
	SF_CASE("function, at the end without a break", "x = 1\nFunction Bar(a)\n  Bar = a\nEnd Function",
		{ "Function Bar", "End Function", "Bar", 0 });
	SF_CASE("modifiers", "Public Sub A()\nEnd Sub\nPrivate Function B()\nEnd Function\nPublic Default Function C()\nEnd Function\n",
		{ "Public Sub A", "End Sub", "A", 0 }, { "Private", "End Function", "B", 0 }, { "Public Default", "End Function", "C", 0 });
	SF_CASE("properties in a class",
		"Class K\n  Public Property Get Name\n    Name = m\n  End Property\n  Property Let Name(v)\n  End Property\n"
		"  Property Set Obj(o)\n  End Property\nEnd Class\n",
		{ "Public Property", "End Property", "Name", 0 }, { "Property Let", "End Property", "Name", 0 },
		{ "Property Set", "End Property", "Obj", 0 });
	SF_CASE("any case", "sub f()\nend sub\nSUB G()\nEND SUB\n", { "sub f", "end sub", "f", 0 }, { "SUB G", "END SUB", "G", 0 });
	SF_CASE("escaped name", "Sub [End]()\nEnd Sub\n", { "Sub", "()\nEnd Sub", "[End]", 0 });
	SF_CASE("attribute in front", "<WebMethod()> Public Function Hi() As String\n  Return \"x\"\nEnd Function\n",
		{ "<WebMethod", "End Function", "Hi", 0 });
}

static void ends(void)
{
	SF_CASE("Exit Sub is not the end", "Sub f()\n  If x Then Exit Sub\n  y\nEnd Sub\n", { "Sub f", "End Sub", "f", 0 });
	SF_CASE("End alone and End If are not", "Sub f()\n  If a Then\n  End If\n  End\nEnd Sub\nz\n", { "Sub f", "End\nEnd Sub", "f", 0 });
	SF_CASE("colon separated", "Sub f() : x = 1 : End Sub\nSub g(): End Sub\n", { "Sub f", "End Sub", "f", 0 },
		{ "Sub g", "End Sub", "g", 0 });
	SF_CASE("continued lines", "Private _\nSub f(a, _\n  b)\nEnd _\nSub\nx\n", { "Private", "End _\nSub", "f", 0 });
	SF_CASE("an underscore that is not a continuation, an open bracket, a stray <",
		"Sub f()\n  x = a _ b\n  [y = 1\n<z\n  [End] = 2\nEnd Sub\n", { "Sub f", "2\nEnd Sub", "f", 0 });
	SF_CASE("a date literal's colon is not a separator", "Sub f()\n  d = #10:30:00# : End Sub\n", { "Sub f", "End Sub", "f", 0 });
	SF_CASE("Declare has no body", "Private Declare Function GetTickCount Lib \"kernel32\" () As Long\nSub f()\nEnd Sub\n",
		{ "Sub f", "End Sub", "f", 0 });
	SF_CASE("MustOverride has no body",
		"MustInherit Class A\n  Public MustOverride Sub M()\n  Public Sub N()\n  End Sub\nEnd Class\n", { "Public Sub N", "End Sub", "N", 0 });
	SF_CASE("interface members have no body",
		"Interface I\n  Sub M()\n  Function F() As Integer\n  Property P As Integer\nEnd Interface\nSub X()\nEnd Sub\n",
		{ "Sub X", "End Sub", "X", 0 });
	SF_CASE("Delegate has no body", "Delegate Sub D(x As Integer)\nSub X()\nEnd Sub\n", { "Sub X", "End Sub", "X", 0 });
	SF_CASE("auto-property has no body, a full one has",
		"Class C\n  Public Property P As Integer\n  Public Property Q As String\n    Get\n      Return q\n    End Get\n"
		"    Set(value As String)\n    End Set\n  End Property\n  ReadOnly Property R() As Integer\n    Get\n    End Get\n  End Property\nEnd Class\n",
		{ "Public Property Q", "End Property", "Q", 0 }, { "ReadOnly", "End Property", "R", 0 });
	SF_CASE("lambdas stay in the method",
		"Sub Main()\n  Dim f = Function(x) x + 1\n  Dim g = Sub(y)\n    Console.WriteLine(y)\n  End Sub\n"
		"  Dim h = Function(z) As Integer\n    Return z\n  End Function\n  g(1)\nEnd Sub\n",
		{ "Sub Main", "g(1)\nEnd Sub", "Main", 0 });
	SF_CASE("a Sub that never ends is closed by the next one, open",
		"Sub a()\n  x\nSub b()\nEnd Sub\n", { "Sub a", "Sub b", "a", 2 }, { "Sub b", "End Sub", "b", 0 });
	SF_CASE("unterminated at the end", "Sub f()\n  x\n", { "Sub f", NULL, "f", 1 });
}

static void literals(void)
{
	SF_NONE("strings and comments", "s = \"Sub x()\"\n' Sub y()\nRem Sub z()\nx = 1 : Rem End Sub\n");
	SF_CASE("End Sub in a string or a comment", "Sub f()\n  s = \"End Sub\"\n  ' End Sub\n  Rem End Sub\nEnd Sub\n",
		{ "Sub f", "Sub\nEnd Sub", "f", 0 });
	SF_NONE("not at a statement start", "x = Sub\nCall Sub\ny.Sub()\n");
}

/* An ASP page: the asp lexer's islands, this strategy. */
#define ASP_CASE(name, src, ...) do { \
	static const struct sf_want w_[] = { __VA_ARGS__ }; \
	sf_check_lang(KGENOME_TEXTUAL_LANG_ASP, name, src, strlen(src), w_, (uint32_t)(sizeof w_ / sizeof w_[0])); \
} while (0)

static void asp(void)
{
	ASP_CASE("a function across islands, markup between", "<html><% Sub f() %>\n<b>html</b>\n<% End Sub %></html>",
		{ "Sub f", "End Sub", "f", 0 });
	ASP_CASE("one island", "<%\nFunction g(x)\n  g = x\nEnd Function\n%>\n<p><% Call g(1) %></p>",
		{ "Function g", "End Function", "g", 0 });
	ASP_CASE("a tag begins a statement", "<%Sub f()%><%End Sub%>", { "Sub f", "End Sub", "f", 0 });
	ASP_CASE("markup that spells Sub is not code", "<% x = 1 %>Sub y()<% %>End Sub<% Sub z() : End Sub %>",
		{ "Sub z", "End Sub", "z", 0 });
	ASP_CASE("If across islands inside a Sub", "<% Sub f() %><% If x Then %>a<% End If %><% End Sub %>",
		{ "Sub f", "End Sub", "f", 0 });
}

static void hostile(void)
{
	sf_hostile("100000 subs", "", "Sub f()\nEnd Sub\n", 100000u, 100000u);
	sf_hostile("100000 subs with no End", "", "Sub f()\n", 100000u, 100000u);
	sf_hostile("100000 multi-line lambdas in one sub", "Sub f()\n", "Dim g = Sub(y)\n", 100000u, 1u);
	sf_hostile("100000 continuations", "Sub f(", "a, _\n", 100000u, 1u);
	sf_hostile("100000 stray End Sub", "", "End Sub\n", 100000u, 0u);
}

int main(int argc, char **argv)
{
	hk_args(argc, argv);
	shapes();
	ends();
	literals();
	asp();
	hostile();
	if (hk_fails) {
		printf("script_funcs_vb: %d FAILED\n", hk_fails);
		return 1;
	}
	printf("script_funcs_vb: ok\n");
	return 0;
}
