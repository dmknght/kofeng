/*
 * objprod.h - the analysis of an object, handed to the rendering of it.
 *
 * A NORMALISED VIEW IS NOT A SECOND PROGRAM. It is the parent with some padding
 * taken out and some text narrowed, scanned as an object of its own so that a
 * rule about strings reads strings. Everything the engine learns about what the
 * PROGRAM is and does - its image (sections, entry), its functions, its symbols,
 * its diagnoses and the graph they were matched on, what it resolves for itself -
 * is true of the parent and the view alike, and is found on the parent, where the
 * image is whole.
 *
 * It cannot be found again on the view, and the reason is not cost. The view is
 * not a loadable image: a zero run collapsed in the middle of a section moves
 * every byte after it away from the address the program says it is at, so a walk
 * or an emulation of the view reads different code from a place that no longer
 * matches. Its header still says where things were. A re-run was measured to
 * give a wrong answer on a PE (the entry came back unresolved and the code region
 * empty - the view lost the parent's verdict), and a right one on an ELF only
 * where nothing happened to collapse ahead of the code.
 *
 * So what a view knows about the program it inherits, product by product, each in
 * the form that fits it:
 *
 *   what is a place (regions, the image description, the entry, the functions)
 *       is CARRIED THROUGH THE TRANSFORM - offsets moved by the boundary table
 *       the transform itself produced (see genotype/image/offmap.h).
 *   what is an answer (the diagnoses that matched, the graph, what a PE
 *       resolves) is SHARED, in the parent's own coordinates, because an answer
 *       has no offset to move. The graph borrows the parent's bytes, so the
 *       share holds a reference on them.
 *
 * Published when the parent's pipeline has finished - which is when every
 * lazily computed product exists - and only for a parent that produced a view.
 * If the parent never computed one (nothing asked), the view does not either:
 * asking on the view would be answering a question about the wrong bytes.
 *
 * Reference counted and immutable once published. The scanner's per-object
 * fields point INTO it for the duration of the view's scan and do not free it.
 */
#ifndef KOFENG_OBJPROD_H
#define KOFENG_OBJPROD_H

#include <stdint.h>

struct kof_scanner;
struct kof_prod;

/*
 * Move the parent's computed analysis out of the scanner into a shared record,
 * and give it to every normalised view the parent produced. A no-op for an
 * object that produced none.
 */
void kof_prod_publish(struct kof_scanner *sc);

/* A view's scan begins: point the scanner's per-object analysis at the shared
 * one, and latch every product so that nothing is derived from the view. */
void kof_prod_adopt(struct kof_scanner *sc, const struct kof_prod *p);

/* Let go of the scanner's borrowed analysis - the inverse of the adopt. */
void kof_prod_unadopt(struct kof_scanner *sc);

void kof_prod_unref(struct kof_prod *p);

#endif /* KOFENG_OBJPROD_H */
