/*
 * nucleo_private.h - what the two halves of the capability vocabulary share.
 *
 * nucleo.c reads an imported NAME, nucleo_sys.c a syscall NUMBER; the socket kind is the
 * one statement both ask. Static inline so that neither pays a call for it.
 */

#ifndef KGENOME_NUCLEO_PRIVATE_H
#define KGENOME_NUCLEO_PRIVATE_H

#include "nucleo.h"

/*
 * WHAT KIND OF SOCKET `socket(domain, type, ...)` MADE, from the first two
 * arguments. One statement of it, read by the syscall and by the named call
 * (kgenome_nucleo_cap_of_call): the Windows socket()/WSASocket* take the same two
 * values in the same order, and AF_UNIX and SOCK_RAW are the same numbers.
 */
static inline uint16_t kgenome_nucleo_sock_kind(const uint64_t *arg, uint8_t *flags)
{
	if ((arg[0] & 0xffu) == KGENOME_NUCLEO_AF_UNIX && flags)
		*flags |= KGENOME_NUCLEO_F_LOCAL;
	if ((arg[1] & 0xfu) == KGENOME_NUCLEO_SOCK_RAW)
		return KGENOME_NUCLEO_NET_RAW;
	if ((arg[1] & 0xfu) == KGENOME_NUCLEO_SOCK_DGRAM && flags)
		*flags |= KGENOME_NUCLEO_F_DGRAM;
	return KGENOME_NUCLEO_NET_OPEN;
}

#endif /* KGENOME_NUCLEO_PRIVATE_H */
