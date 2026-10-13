/*
 * tests/sigs/syndromes/dropper_00.c - a fixture: a sample that was a dropper and
 * on which the rwx-region disease fired. See rootkit_00.c.
 */

KOF_DECLARE_SYNDROME_TYPE(KOF_MALTYPE_DROPPER);
KOF_DECLARE_SYNDROME_HAS("exec/rwx-region");
