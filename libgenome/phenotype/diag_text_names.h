/*
 * diag_text_names.h - the names a script calls, told once each, as a stream that a caller can feed from a scan it already makes.
 *
 * kgenome_diag_text_names scans a text to learn the names its calls have in the language's table. A caller that scans the same text for another reason
 * (the graph, the constants) asks that scan to tell the names as it goes - on_node of kgenome_diag_text_req is kgenome_diag_text_names_node - instead of scanning again.
 * What is told is the table's spelling of each name, each once (by its id: a name met again is not told again), in the order the walk meets them.
 */
#ifndef KGENOME_DIAG_TEXT_NAMES_H
#define KGENOME_DIAG_TEXT_NAMES_H

#include <stdint.h>

struct kgenome_diag_text_names_acc;

/* A tell for the language `lang`: `fn` is called for each distinct name (the table's spelling and its length; the bytes are the library's and stay valid). NULL for a language with no row or no memory. */
struct kgenome_diag_text_names_acc *kgenome_diag_text_names_new(uint32_t lang, void (*fn)(void *user, const char *name, uint32_t len), void *user);
/* The on_node callback of a scan: `acc` is the tell. */
void kgenome_diag_text_names_node(void *acc, const char *name);
void kgenome_diag_text_names_free(struct kgenome_diag_text_names_acc *acc);

#endif
