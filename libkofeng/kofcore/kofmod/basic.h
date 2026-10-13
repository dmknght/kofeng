/*
 * basic.h - the two sentinels and the architecture list.
 *
 * THE ABI RE-EXPORTS kgenome's DEFINITION. KOF_NA, KOF_BROKEN and the
 * architecture list are what the code reader (the decoders, the cursor and the
 * image arithmetic) is written against, so they are defined once, in
 * libgenome/celllysis/arch.h, with the notes on what each sentinel means.
 * kofsig.h includes this and so does every module through it.
 */
#ifndef KOFENG_BASIC_H
#define KOFENG_BASIC_H

#include <celllysis/arch.h>

#endif /* KOFENG_BASIC_H */
