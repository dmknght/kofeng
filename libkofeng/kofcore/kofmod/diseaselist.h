#ifndef KOFMOD_DISEASELIST_H
#define KOFMOD_DISEASELIST_H

/*
 * kofmod/diseaselist.h - THE LIST OF DISEASES: what malware DOES (ACT) and to WHAT (OBJ).
 *
 * A disease is a PAIR of values from the two lists below and nothing else: no free-text name, no path, so there is no spelling
 * to get wrong, no two ways to write one disease, and a comparison is a comparison of numbers. `scan` on `network` is the code
 * that looks for hosts; `hidden` on `process` is the rootkit that hides one; `execution` on `process` starts one here and
 * `execution` on `memory` runs code from memory: the OBJ is what tells them apart. EXECUTION is code running on THIS host (spawn,
 * shell, run from memory, load a file). SCAN is probing: hosts, services, whether credentials work. HOW A SAMPLE GOT IN (an exploit, a
 * delivery) and attacks on other machines are not activities of this list: that is the diagnose's type and family. A brute force that
 * succeeds is for executing code remotely, so it is not a value either. The type of malware stays the engine's kof_maltype
 * (kofverdict.h), declared beside the disease.
 *
 * Both lists belong to the engine, like kof_maltype: a researcher picks, never types. Adding a value is a deliberate change here.
 * The ACT list is the ATT&CK tactics merged for malware (reconnaissance and discovery are `scan`; collection, exfiltration and
 * credential access are `steal`; privilege escalation is `escalation`, flooding, deleting logs and wiping are `destruction`; resource
 * development and initial access are not what a sample DOES). The OBJECT of an escalation is by default `system` or `kernel` (services
 * are in `system`).
 * The OBJ list is the capability groups the analysis already knows (libgenome/celllysis/capability_word.h), merged where one word
 * serves: pipes go with `file`, threads and namespaces with `process`, kernel modules and eBPF with `kernel`, services and the
 * like with `system`. `crypto`, `library` and `credential` are not objects (a uid is the process's, a stolen password is `steal`).
 * "obj" HERE is the thing an activity acts on, not the scanner's object (struct kof_obj_ctx).
 *
 * Value 0 of both is NONE (not set). A disease needs an ACT; the OBJ is optional.
 */

#include <stddef.h>
#include <stdint.h>

#define KOF_DISEASE_ACT_LIST(X)                                              \
	X(KOF_DISEASE_ACT_SCAN,                 "scan")                      \
	X(KOF_DISEASE_ACT_STEAL,                "steal")                     \
	X(KOF_DISEASE_ACT_EXECUTION,            "execution")                 \
	X(KOF_DISEASE_ACT_PERSISTENCE,          "persistence")               \
	X(KOF_DISEASE_ACT_ESCALATION,           "escalation")                \
	X(KOF_DISEASE_ACT_EVASION,              "evasion")   /* anti-VM, anti-debug, packing */ \
	X(KOF_DISEASE_ACT_HIDDEN,               "hidden")    /* hiding on the host: rootkit style */ \
	X(KOF_DISEASE_ACT_C2,                   "c2")                        \
	X(KOF_DISEASE_ACT_DESTRUCTION,          "destruction") /* flood, deleting logs, wiping */

#define KOF_DISEASE_OBJ_LIST(X)                                              \
	X(KOF_DISEASE_OBJ_NETWORK,  "network")                               \
	X(KOF_DISEASE_OBJ_FILE,     "file")      /* and pipes */             \
	X(KOF_DISEASE_OBJ_MEMORY,   "memory")    /* the bytes of an address space, one's own or another's */ \
	X(KOF_DISEASE_OBJ_PROCESS,  "process")   /* the process itself: start, list, hide, trace; threads, namespaces */ \
	X(KOF_DISEASE_OBJ_REGISTRY, "registry")                              \
	X(KOF_DISEASE_OBJ_KERNEL,   "kernel")    /* code in the kernel: modules, hooks, eBPF */ \
	X(KOF_DISEASE_OBJ_SYSTEM,   "system")    /* the OS's own configuration: services, scheduled jobs, startup, accounts */ \
	X(KOF_DISEASE_OBJ_INPUT,    "input")     /* keys, screen */

enum kof_disease_act {
	KOF_DISEASE_ACT_NONE = 0,
#define KOF_DISEASE_ACT_X_ENUM(name, word) name,
	KOF_DISEASE_ACT_LIST(KOF_DISEASE_ACT_X_ENUM)
#undef KOF_DISEASE_ACT_X_ENUM
	KOF_DISEASE_ACT_COUNT          /* one past the last: every table of these is expanded from the list */
};

enum kof_disease_obj {
	KOF_DISEASE_OBJ_NONE = 0,
#define KOF_DISEASE_OBJ_X_ENUM(name, word) name,
	KOF_DISEASE_OBJ_LIST(KOF_DISEASE_OBJ_X_ENUM)
#undef KOF_DISEASE_OBJ_X_ENUM
	KOF_DISEASE_OBJ_COUNT
};

/* The word of a value, or "none" for NONE and for a value from outside the list. */
static inline const char *kof_disease_act_name(uint32_t act)
{
	switch (act) {
#define KOF_DISEASE_ACT_X_NAME(name, word) case name: return word;
	KOF_DISEASE_ACT_LIST(KOF_DISEASE_ACT_X_NAME)
#undef KOF_DISEASE_ACT_X_NAME
	default: return "none";
	}
}

static inline const char *kof_disease_obj_name(uint32_t obj)
{
	switch (obj) {
#define KOF_DISEASE_OBJ_X_NAME(name, word) case name: return word;
	KOF_DISEASE_OBJ_LIST(KOF_DISEASE_OBJ_X_NAME)
#undef KOF_DISEASE_OBJ_X_NAME
	default: return "none";
	}
}

static inline int kof_disease_word_eq_(const char *a, const char *b)
{
	while (*a && *a == *b) {
		a++;
		b++;
	}
	return *a == *b;
}

/* The way back: a whole word to its value. 1 and *out set on a hit, 0 on an unknown word (never a sentinel: NONE is not a word). */
static inline int kof_disease_act_from_name(const char *s, uint8_t *out)
{
#define KOF_DISEASE_ACT_X_FROM(name, word) if (kof_disease_word_eq_(s, word)) { *out = (uint8_t)(name); return 1; }
	KOF_DISEASE_ACT_LIST(KOF_DISEASE_ACT_X_FROM)
#undef KOF_DISEASE_ACT_X_FROM
	return 0;
}

static inline int kof_disease_obj_from_name(const char *s, uint8_t *out)
{
#define KOF_DISEASE_OBJ_X_FROM(name, word) if (kof_disease_word_eq_(s, word)) { *out = (uint8_t)(name); return 1; }
	KOF_DISEASE_OBJ_LIST(KOF_DISEASE_OBJ_X_FROM)
#undef KOF_DISEASE_OBJ_X_FROM
	return 0;
}

/*
 * THE DISPLAY OF A WORD, one function for every place a word of either list is SHOWN (the tick menus and grids, the table, a message):
 * the first letter upper case ("Scan", "Network"); a word that holds a digit is upper-cased whole ("c2" -> "C2"); a hyphen stays. The stored
 * words stay lower case (they are what a file and kof_disease_*_from_name read). Writes at most cap-1 characters and a NUL; returns the
 * length written (0 and an empty string when cap is 0 or word is NULL).
 */
static inline size_t kof_disease_display(const char *word, char *out, size_t cap)
{
	size_t i = 0;
	int digit = 0;

	if (!cap)
		return 0;
	out[0] = 0;
	if (!word)
		return 0;
	for (i = 0; word[i]; i++)
		if (word[i] >= '0' && word[i] <= '9')
			digit = 1;
	for (i = 0; word[i] && i + 1 < cap; i++) {
		char c = word[i];

		out[i] = c >= 'a' && c <= 'z' && (digit || i == 0) ? (char)(c - 'a' + 'A') : c;
	}
	out[i] = 0;
	return i;
}

#endif /* KOFMOD_DISEASELIST_H */
