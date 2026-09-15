/*
 * wfid.h - the Windows half of kof_fid_of. See wfid.c.
 *
 * There is nothing here but an include, and that is the point: the contract is
 * declared once in fidset.h, beside the struct it fills, and this file exists
 * so the Windows collector has a header of its own the way libkofantarc has
 * afid.h. A caller includes neither - it includes fidset.h and calls the name.
 */

#ifndef KOFGRILLE_WFID_H
#define KOFGRILLE_WFID_H

#include "../libkoforbit/koffridge/fidset.h"

#endif /* KOFGRILLE_WFID_H */
