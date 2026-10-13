/*
 * tests/sigs/syndromes/vd_trojan_00.c - a fixture: a sample that was a trojan and
 * on which verdict/gamma and verdict/delta fired. See vd_miner_00.c.
 */

KOF_DECLARE_SYNDROME_TYPE(KOF_MALTYPE_TROJAN);
KOF_DECLARE_SYNDROME_HAS("verdict/gamma");
KOF_DECLARE_SYNDROME_HAS("verdict/delta");
