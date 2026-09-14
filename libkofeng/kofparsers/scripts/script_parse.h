/*
 * script_parse.h - which interpreter a text file is written for.
 *
 * The odd one out in the parser table, and deliberately so: it reads no
 * structure and carves no region, because a script has neither. What it
 * produces is ONE FACT - ctx->subtype, the kind - and that fact exists for a
 * precondition rather than for a module to read: nobody runs a PHP signature
 * against a Python file, and the host can now decline to offer it one.
 *
 * IT IS IN THE TABLE BECAUSE THE TABLE IS THE SNIFF CHAIN. There is nowhere
 * else an object gets looked at and given a format, so a script that nothing
 * declared - a .php on disk - could only ever come out unrecognised. It sits
 * LAST among the rows that really sniff, so every format with a magic number
 * has already had its turn and this one only sees what nothing else claimed.
 */

#ifndef KOFENG_SCRIPT_PARSE_H
#define KOFENG_SCRIPT_PARSE_H

#include <kofmod/script.h>
#include <kofmod/kofsig.h>
#include "../../core/kofcore.h"

/*
 * Returns non-zero if these bytes are a script.
 *
 * TWO SIGNALS, BOTH OF WHICH NAME AN INTERPRETER OUTRIGHT - a "#!" line, or a
 * PHP open tag. Neither is a guess: a file starting "#!" is asking a kernel to
 * run something, and "<?php" is not a thing that occurs in passing.
 *
 * What is NOT here is any attempt to recognise a language from its syntax. A
 * Python file with no shebang looks like prose with colons in it, and a rule
 * that leant on indentation or on the word "def" would claim README files. Such
 * a file stays unrecognised, which costs nothing that is not already lost.
 */
int kof_script_sniff(kof_buf file);

/*
 * Fills info and sets ctx->format, ctx->subtype and ctx->file_header.
 *
 * NEVER FAILS once the sniff accepted. An interpreter this build has no name
 * for is KOF_SCRIPT_ANY, which is an answer: the object IS a script, and a rule
 * that declares no subtype still wants to see it.
 */
int kof_script_parse(kof_buf file, struct kof_script_info *info,
		     struct kof_obj_ctx *ctx);

const char *kof_script_region_name(uint32_t bit);
const char *kof_script_anomaly_name(unsigned index);

/* THE REGION LIST, where everything that needs it can see it - the same
 * arrangement every other format uses, so ksigbuilder turns the name a
 * signature writes back into a bit from this list instead of a hand copy. */
#define SCRIPT_REGIONS(X)          \
	X(KOF_SCAN_SCRIPT_HEADER)  \
	X(KOF_SCAN_SCRIPT_BODY)    \
	X(KOF_SCAN_SCRIPT_MARKUP)

/* Three regions, and they partition the object exactly - see script_parse.c.
 * MARKUP is empty for everything that is not a server page. */
extern const uint32_t kof_script_region_bits[];
#define KOF_SCRIPT_REGION_COUNT 3u

#endif /* KOFENG_SCRIPT_PARSE_H */
