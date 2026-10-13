/*
 * tests/sigs/syndromes/vd_miner_00.c - a fixture: a sample that was a miner and
 * on which verdict/alpha and verdict/beta fired. One of four exemplars that
 * tests/unit/verdict_branches.c reads sets of diseases against; alpha is shared
 * with vd_botnet_00 and gamma with vd_trojan_00 ON PURPOSE - a behaviour two
 * types show is what makes a verdict ambiguous.
 */

KOF_DECLARE_SYNDROME_TYPE(KOF_MALTYPE_MINER);
KOF_DECLARE_SYNDROME_HAS("verdict/alpha");
KOF_DECLARE_SYNDROME_HAS("verdict/beta");
