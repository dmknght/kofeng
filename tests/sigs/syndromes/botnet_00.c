/*
 * tests/sigs/syndromes/botnet_00.c - a fixture: a sample that was a botnet and on
 * which the flood-network/udp disease fired. See rootkit_00.c.
 */

KOF_DECLARE_SYNDROME_TYPE(KOF_MALTYPE_BOTNET);
KOF_DECLARE_SYNDROME_HAS("flood-network/udp");
