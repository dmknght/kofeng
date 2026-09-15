/*
 * afid.h - what Linux says about a file, as an identity the cache can key on.
 *
 * THE PLATFORM HALF OF struct kof_fid, AND IT LIVES HERE FOR A REASON.
 *
 * The set that consumes it - libkoforbit's fidset - must build on both
 * platforms and knows nothing about either. So each side fills the struct its
 * own way and orbit only ever sees the filled struct: this is one stat, and
 * libkofgrille's is one GetFileInformationByHandle.
 *
 * That split is the correction of a fault the old identity had. It was declared
 * in orbit and implemented there too, with an #ifdef - and the only code that
 * ever filled the Windows half was a private static inside a Windows-only tool.
 * Half a documented contract had no implementation and the other half was
 * unreachable from anywhere else.
 *
 * NOTHING HERE READS A BYTE OF THE FILE. That is the whole bargain: an identity
 * costs one stat, and what makes it trustworthy is that something is watching
 * for writes - see the note at the top of fidset.h, which is where the cost of
 * that bargain is written down.
 */

#ifndef KOFANTARC_AFID_H
#define KOFANTARC_AFID_H

#include "../libkoforbit/koffridge/fidset.h"

/*
 * kof_fid_of ITSELF IS DECLARED IN fidset.h, not here.
 *
 * It is one name with two definitions - this file's and libkofgrille/wfid.c's -
 * so it is declared once beside the struct it fills, the way kof_walk_open is.
 * A caller includes fidset.h and calls the name; it never includes this header
 * to reach it and never learns which platform answered.
 *
 * NANOSECONDS, not seconds. Two writes inside the same second are two different
 * contents, and a one-second identity cannot tell them apart - which is a
 * window an attacker chooses rather than one they have to wait for.
 */

/* The same for a file already open, which is what a scanner holds by the time
 * it wants to ask. Saves a second path lookup and closes the window between
 * naming a file and opening it. */
int kofa_fid_of_fd(int fd, struct kof_fid *out);

#endif /* KOFANTARC_AFID_H */
