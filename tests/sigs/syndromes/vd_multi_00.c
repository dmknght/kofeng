/*
 * tests/sigs/syndromes/vd_multi_00.c - a fixture: a sample that was BOTH a
 * rootkit and an exploit, and on which verdict/eps and verdict/zeta fired - the
 * exemplar that makes a verdict name two types. See vd_miner_00.c.
 */

KOF_DECLARE_SYNDROME_TYPE(KOF_MALTYPE_ROOTKIT);
KOF_DECLARE_SYNDROME_TYPE(KOF_MALTYPE_EXPLOIT);
KOF_DECLARE_SYNDROME_HAS("verdict/eps");
KOF_DECLARE_SYNDROME_HAS("verdict/zeta");
