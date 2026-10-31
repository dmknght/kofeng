#ifndef KX_GRAPH_CHAIN_GOLD_H
#define KX_GRAPH_CHAIN_GOLD_H

/* the frozen picture of kx_graph_chain.c: the function made from bytes, drawn with the engine's rows (plain ASCII set) */
static const char GOLD_KILL[] =
	"    .-----------------------------.\n"
	"    | B0 0x40 n_insn=2 JUMP       |\n"
	"    | in=0 out=1 call=0 #3749646b |\n"
	"    `-----------------------------'\n"
	"                   |\n"
	"                   v\n"
	"    .-----------------------------.\n"
	"    | B2 @ 0x4d n_insn=2 COND     |\n"
	"    | in=3 out=2 call=0 #c0383a20 |\n"
	"    `-----------------------------'\n"
	"     ^^            F             T\n"
	".====':            |             '-----.\n"
	": .==='            |                   |\n"
	": :                v                   v\n"
	": : .-----------------------------.   .-----------------------------.\n"
	": : | B3 0x54 n_insn=3 COND       |   | B1 0x46 n_insn=2 COND       |\n"
	": : | in=1 out=2 call=1 #2e494866 |   | in=1 out=2 call=0 #2e494866 |\n"
	": : | call outside the object     |   `-----------------------------'\n"
	": : `-----------------------------'    FT\n"
	": :  T                           F     :|\n"
	"'=+==+===========================+====='|\n"
	"  '=='                           |      |\n"
	"                                 v      v\n"
	"                     .-----------------------------.\n"
	"                     | B4 0x60 n_insn=2 EXIT       |\n"
	"                     | in=2 out=0 call=0 #8abb9571 |\n"
	"                     `-----------------------------'\n";

#endif /* KX_GRAPH_CHAIN_GOLD_H */
