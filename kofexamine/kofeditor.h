/*
 * kofeditor.h - the diagnose panel's draft model, apart from the viewer's.
 *
 * WHY THIS IS A FILE OF ISOLATED STATE.
 *
 * The draft a researcher builds - strings, blocks, matchers, conditions and
 * the tag each condition finds - is a model, and the panes, the tree, the input
 * handling and the disassembler are not. Nothing forced them apart, so nothing
 * kept them apart: a draft function reached into the selection, a drawing
 * function reached into the draft, and "what is the model" had no answer that
 * could be checked. The functions here touch no viewer state at all, or only
 * the draft and the object a marker was taken from.
 *
 * Nothing here writes a file. The panel previews the diagnose a draft stands
 * for; it does not save one.
 *
 * WHAT IS NOT HERE.
 *
 * Drawing and input. A model that knows how wide a column is, or which row was
 * clicked, is the same tangle under a new name.
 *
 * Anything the engine already answers. Where a marker is and which region that
 * is come from kof_locate_str in kofinspect.h, because two answers to one
 * question is how the panel came to call a marker absent that the scan finds
 * every time.
 */

#ifndef KOF_KOFEDITOR_H
#define KOF_KOFEDITOR_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <kofmod/kofsig.h>
#include <kofmod/kofsym.h>
#include <kofmod/kofmutation.h>
#include <kofeng.h>
#include "kofinspect.h"
#include "../libkofeng/analyzers/parsers/binaries/funcs.h"
#include "../libkofeng/analyzers/codenotes.h"
#include "../libkofeng/databases/tagsrc.h"


/* The parts, in dependency order: each needs what the ones above it declare.
 * kofeditor_proto_types.h  the draft model's types      (prototype)
 * kofeditor_object.h       struct object
 * kofeditor_proto_fn.h     struct kof_editor and the functions on a draft (prototype) */
#include "kofeditor_proto_types.h"
#include "kofeditor_object.h"
#include "kofeditor_proto_fn.h"

#endif /* KOF_KOFEDITOR_H */
