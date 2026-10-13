/*
 * tests/sigs/syndromes/vd_botnet_00.c - a fixture: a sample that was a botnet and
 * on which verdict/alpha and verdict/gamma fired. See vd_miner_00.c.
 */

KOF_DECLARE_SYNDROME_TYPE(KOF_MALTYPE_BOTNET);
KOF_DECLARE_SYNDROME_HAS("verdict/alpha");
KOF_DECLARE_SYNDROME_HAS("verdict/gamma");
