/*
 * api_engine_constants.c - the numeric MACROS of the engine's public headers, held to
 * what they stand for.
 *
 * Three kinds of statement, chosen by what the family is:
 *
 *   FLAGS      a family of region masks, anomaly bits or option flags is a set of
 *              single bits that collide with none of its siblings. A flag that is two
 *              bits, or the same bit as another, is a rule that tests something it did
 *              not mean to.
 *   ENUMS      a family of identifiers (formats, architectures, capability words,
 *              syscalls, levels) gives every member its own value; two names for one
 *              number is two meanings for one stored byte.
 *   ABI        the numbers of the module ABI (everything under kofcore/) are written into
 *              packs built by one tool and read by another, and a change moves what an
 *              existing pack means. Each is pinned to the value it has in the ABI
 *              (KOFSIG_ABI_VERSION says which) so that moving one is a decision that
 *              fails here, not something a rebuild hides. The values are those of
 *              the ABI this tree carries; a deliberate change updates this table in
 *              the same commit as KOFSIG_ABI_VERSION. A family whose members are
 *              meant to be aliases (a count, a mask of the others) is pinned member by
 *              member for the same reason.
 *
 * WHAT IS PINNED, decided by who can see the value (the triage of 2026-10-14, 359 pins
 * down to 334 and 19 limit families of executed checks removed): a value is pinned when it
 * crosses the engine's boundary into something that outlives or leaves a build - bytes of a
 * pack, a diagnose, a symbol or graph block or a process record; a module blob, which has the
 * value compiled in (region masks, capability groups, arch and format ids, flags, the
 * sentinels); a field the engine writes into a struct a module reads (the ids, the versions,
 * the array dimensions that fix a struct's layout); the hash constants the builder uses for
 * the ids it writes into packs. A value is NOT pinned when it only bounds the engine's own
 * work or is a number the parser alone uses: limits, ratios, search windows, planning sizes,
 * and the fixed numbers of an outside file format (tar's block, xz's header length) that no
 * tool outside reads from here. Raising a limit breaks nothing that was built before; pinning
 * it made that change fail here, and the single-bit check on a family of limits was failing
 * a limit for not being a power of two.
 *
 * The table is grouped by header and by the stem of the name; the harness below walks
 * it. Constants that are limits of the engine's own tables (not ABI, not a flag set)
 * are not listed: a number that only has to be big enough has nothing to assert but
 * itself, and docs/api_coverage_engine.txt says so for each.
 */

#include "hostile_engine.h"
#include "known_miss.h"

#include <stdint.h>

#include "../../libkofeng/kofeng.h"
#include "../../libkofeng/kofcore/kofcore.h"
#include "../../libkofeng/kofcore/koftypes.h"
#include "../../libkofeng/kofcore/kofmod/kofsig.h"
#include "../../libkofeng/analyzers/diseases/msf_elf64.h"
#include "../../libkofeng/analyzers/diseases/msf_pe.h"
#include "../../libkofeng/analyzers/parsers/containers/arj_parse.h"
#include "../../libkofeng/analyzers/parsers/containers/bz2_parse.h"
#include "../../libkofeng/analyzers/parsers/containers/cab_parse.h"
#include "../../libkofeng/analyzers/parsers/containers/chm_parse.h"
#include "../../libkofeng/analyzers/parsers/containers/docole_parse.h"
#include "../../libkofeng/analyzers/parsers/containers/gzip_parse.h"
#include "../../libkofeng/analyzers/parsers/containers/lha_parse.h"
#include "../../libkofeng/analyzers/parsers/containers/lnk_parse.h"
#include "../../libkofeng/analyzers/parsers/containers/rar_parse.h"
#include "../../libkofeng/analyzers/parsers/containers/reg_parse.h"
#include "../../libkofeng/analyzers/parsers/containers/rtf_parse.h"
#include "../../libkofeng/analyzers/parsers/containers/sevenzip_parse.h"
#include "../../libkofeng/analyzers/parsers/containers/tar_parse.h"
#include "../../libkofeng/analyzers/parsers/containers/xz_parse.h"
#include "../../libkofeng/analyzers/parsers/containers/zip_parse.h"
#include "../../libkofeng/analyzers/parsers/kofformat.h"
#include "../../libkofeng/analyzers/parsers/scripts/scantext.h"
#include "../../libkofeng/analyzers/parsers/scripts/script_parse.h"
#include "../../libkofeng/databases/diagsrc.h"
#include "../../libkofeng/databases/syndsrc.h"
#include "../../libkofeng/detectors/linkage/kofdiag.h"
#include "../../libkofeng/detectors/pattern/kofmatch.h"
#include "../../libkofeng/detectors/pattern/kofmultimatch.h"
#include "../../libkofeng/kofcore/kofdebug.h"
#include "../../libkofeng/kofcore/kofhash.h"
#include "../../libkofeng/kofcore/kofmod/amsi.h"
#include "../../libkofeng/kofcore/kofmod/arj.h"
#include "../../libkofeng/kofcore/kofmod/aspack_tab.h"
#include "../../libkofeng/kofcore/kofmod/bz2.h"
#include "../../libkofeng/kofcore/kofmod/cab.h"
#include "../../libkofeng/kofcore/kofmod/cell.h"
#include "../../libkofeng/kofcore/kofmod/chm.h"
#include "../../libkofeng/kofcore/kofmod/clr.h"
#include "../../libkofeng/kofcore/kofmod/docole.h"
#include "../../libkofeng/kofcore/kofmod/elf.h"
#include "../../libkofeng/kofcore/kofmod/emu_harvest.h"
#include "../../libkofeng/kofcore/kofmod/ep_shape.h"
#include "../../libkofeng/kofcore/kofmod/gzip.h"
#include "../../libkofeng/kofcore/kofmod/heur.h"
#include "../../libkofeng/kofcore/kofmod/infected.h"
#include "../../libkofeng/kofcore/kofmod/kofabi.h"
#include "../../libkofeng/kofcore/kofmod/kofcap.h"
#include "../../libkofeng/kofcore/kofmod/kofchild.h"
#include "../../libkofeng/kofcore/kofmod/kofcure.h"
#include "../../libkofeng/kofcore/kofmod/kofdeclare.h"
#include "../../libkofeng/kofcore/kofmod/kofdiagnose.h"
#include "../../libkofeng/kofcore/kofmod/kofdiagtree.h"
#include "../../libkofeng/kofcore/kofmod/kofentry.h"
#include "../../libkofeng/kofcore/kofmod/kofmodemu.h"
#include "../../libkofeng/kofcore/kofmod/kofmutation.h"
#include "../../libkofeng/kofcore/kofmod/kofname.h"
#include "../../libkofeng/kofcore/kofmod/kofobjfmt.h"
#include "../../libkofeng/kofcore/kofmod/kofregion.h"
#include "../../libkofeng/kofcore/kofmod/kofsym.h"
#include "../../libkofeng/kofcore/kofmod/kofverdict.h"
#include "../../libkofeng/kofcore/kofmod/lha.h"
#include "../../libkofeng/kofcore/kofmod/lnk.h"
#include "../../libkofeng/kofcore/kofmod/pdf.h"
#include "../../libkofeng/kofcore/kofmod/pe.h"
#include "../../libkofeng/kofcore/kofmod/pe_reassemble.h"
#include "../../libkofeng/kofcore/kofmod/proc.h"
#include "../../libkofeng/kofcore/kofmod/rar.h"
#include "../../libkofeng/kofcore/kofmod/reg.h"
#include "../../libkofeng/kofcore/kofmod/rtf.h"
#include "../../libkofeng/kofcore/kofmod/script.h"
#include "../../libkofeng/kofcore/kofmod/sevenzip.h"
#include "../../libkofeng/kofcore/kofmod/tar.h"
#include "../../libkofeng/kofcore/kofmod/upx_method.h"
#include "../../libkofeng/kofcore/kofmod/xz.h"
#include "../../libkofeng/kofcore/kofmod/zip.h"
#include "../../libkofeng/kofcore/kofobjname.h"
#include "../../libkofeng/kofcore/kofoption.h"
#include "../../libkofeng/kofcore/kofplatform_file.h"
#include "../../libkofeng/kofcore/kofresult.h"
#include "../../libkofeng/kofcore/runlist.h"
#include "../../libkofeng/verdictor/verdict.h"

struct kc {
	const char *name;
	uint64_t    val;
};

struct group {
	const char     *what;
	const struct kc *m;
	unsigned        n;
	int             kind;    /* 0 flags, 1 enum, 2 pinned */
};

#define K(x) { #x, (uint64_t)(x) }

static const struct kc g000[] = {
	K(MSF_ELF64_BASE), K(MSF_ELF64_HDR),
};
static const struct kc g001[] = {
	K(MSF_PE_BASE32), K(MSF_PE_BASE64), K(MSF_PE_RVA),
};
static const struct kc g003[] = {
	K(KOF_DIAG_MATCH_NO), K(KOF_DIAG_MATCH_UNKNOWN), K(KOF_DIAG_MATCH_YES),
};
static const struct kc g004[] = {
	K(KOF_MEMO_ABSENT), K(KOF_MEMO_NONE), K(KOF_MEMO_PRESENT),
	K(KOF_MEMO_UNKNOWN),
};
static const struct kc g008[] = {
	K(KOF_HASH_INIT), K(KOF_HASH_PRIME),
};
static const struct kc g009[] = {
	K(KOF_ERR_ARG), K(KOF_ERR_OPEN), K(KOF_ERR_READ),
};
static const struct kc g010[] = {
	K(KOF_SCAN_AMSI_CLAIMED),
};
static const struct kc g011[] = {
	K(KOF_ARJ_ANOM_COUNT),
};
static const struct kc g012[] = {
	K(KOF_ARJ_INFO_VERSION),
};
static const struct kc g014[] = {
	K(KOF_SCAN_ARJ_CLAIMED),
};
static const struct kc g017[] = {
};
static const struct kc g018[] = {
	K(KOF_BZ2_ANOM_COUNT),
};
static const struct kc g019[] = {
	K(KOF_BZ2_INFO_VERSION),
};
static const struct kc g020[] = {
	K(KOF_SCAN_BZ2_CLAIMED),
};
static const struct kc g021[] = {
	K(KOF_CAB_ANOM_COUNT),
};
static const struct kc g022[] = {
	K(KOF_CAB_INFO_VERSION),
};
static const struct kc g023[] = {
	K(KOF_CAB_MAX_NAME),
};
static const struct kc g024[] = {
	K(KOF_SCAN_CAB_CLAIMED),
};
static const struct kc g025[] = {
	K(CELL_JMP), K(CELL_XOR),
};
static const struct kc g026[] = {
	K(CELL_O_MEM),
};
static const struct kc g027[] = {
	K(KOF_ARCH_ANY), K(KOF_ARCH_ARC), K(KOF_ARCH_ARM),
	K(KOF_ARCH_ARM64), K(KOF_ARCH_COUNT), K(KOF_ARCH_CRIS),
	K(KOF_ARCH_M68K), K(KOF_ARCH_MICROBLAZE), K(KOF_ARCH_MIPS),
	K(KOF_ARCH_MIPS64), K(KOF_ARCH_OR1K), K(KOF_ARCH_OTHER),
	K(KOF_ARCH_PPC), K(KOF_ARCH_PPC64), K(KOF_ARCH_RISCV32),
	K(KOF_ARCH_RISCV64), K(KOF_ARCH_SH), K(KOF_ARCH_SPARC),
	K(KOF_ARCH_SPARC64), K(KOF_ARCH_X86), K(KOF_ARCH_XTENSA),
};
static const struct kc g028[] = {
	K(KOF_ARCH_X86_64),
};
static const struct kc g029[] = {
	K(KOF_BROKEN), K(KOF_NA),
};
static const struct kc g030[] = {
	K(KOF_CHM_ANOM_COUNT),
};
static const struct kc g031[] = {
	K(KOF_CHM_INFO_VERSION),
};
static const struct kc g034[] = {
	K(KOF_SCAN_CHM_CLAIMED),
};
static const struct kc g035[] = {
	K(KOF_SCAN_CLR_BLOB), K(KOF_SCAN_CLR_CLAIMED), K(KOF_SCAN_CLR_HEADER),
	K(KOF_SCAN_CLR_RESOURCE), K(KOF_SCAN_CLR_STRINGS), K(KOF_SCAN_CLR_TABLES),
	K(KOF_SCAN_CLR_US),
};
static const struct kc g036[] = {
	K(KOF_DOCOLE_ANOM_COUNT),
};
static const struct kc g037[] = {
	K(KOF_DOCOLE_INFO_VERSION),
};
static const struct kc g039[] = {
	K(KOF_DOCOLE_MAX_DEPTH),
};
static const struct kc g042[] = {
	K(KOF_SCAN_DOCOLE_CLAIMED), K(KOF_SCAN_DOCOLE_CONTENT), K(KOF_SCAN_DOCOLE_STRUCT),
};
static const struct kc g043[] = {
	K(KOF_ELFDATA_BE),
};
static const struct kc g044[] = {
	K(KOF_ELF_ANOM_SECTAB_MISSING),
};
static const struct kc g045[] = {
	K(KOF_ELF_ANOM_SEC_PAST_EOF),
};
static const struct kc g046[] = {
	K(KOF_ELF_ANOM_SHOFF_PAST_EOF),
};
static const struct kc g047[] = {
	K(KOF_ELF_CORE), K(KOF_ELF_DYN), K(KOF_ELF_EXEC),
	K(KOF_ELF_NONE), K(KOF_ELF_REL),
};
static const struct kc g049[] = {
	K(KOF_PERM_R), K(KOF_PERM_W), K(KOF_PERM_X),
};
static const struct kc g050[] = {
	K(KOF_SCAN_ELF_CLAIMED), K(KOF_SCAN_ELF_CODE), K(KOF_SCAN_ELF_DATA),
	K(KOF_SCAN_ELF_HEADERS), K(KOF_SCAN_ELF_NOLOAD), K(KOF_SCAN_ELF_UNCLAIMED),
};
static const struct kc g051[] = {
	K(KOF_SCAN_ELF_SLIB_CODE), K(KOF_SCAN_ELF_SLIB_DATA),
};
static const struct kc g053[] = {
	K(EPS_MAX),
};
static const struct kc g054[] = {
	K(KOF_GZIP_ANOM_COUNT),
};
static const struct kc g055[] = {
	K(KOF_GZIP_DEFLATE),
};
static const struct kc g056[] = {
	K(KOF_GZIP_INFO_VERSION),
};
static const struct kc g058[] = {
	K(KOF_SCAN_GZIP_CLAIMED),
};
static const struct kc g059[] = {
	K(KOF_ENG_USE_PATHOGEN),
};
static const struct kc g060[] = {
	K(KOF_INF_BODY), K(KOF_INF_DAMAGE),
};
static const struct kc g061[] = {
	K(KOFSIG_ABI_MIN), K(KOFSIG_ABI_VERSION),
};
static const struct kc g062[] = {
	K(KOF_FLOWF_WX),
};
static const struct kc g063[] = {
	K(KOF_NUCLEO_ACTION_READ), K(KOF_NUCLEO_ACTION_WRITE),
};
static const struct kc g064[] = {
	K(KOF_NUCLEO_ALLOC), K(KOF_NUCLEO_BACKGROUND), K(KOF_NUCLEO_CAPTURE),
	K(KOF_NUCLEO_CRYPTO), K(KOF_NUCLEO_DNS), K(KOF_NUCLEO_HEAP),
	K(KOF_NUCLEO_HOOK), K(KOF_NUCLEO_JAIL), K(KOF_NUCLEO_MEMFD),
	K(KOF_NUCLEO_PIPE), K(KOF_NUCLEO_PTRACE), K(KOF_NUCLEO_READ),
	K(KOF_NUCLEO_RESOLVE), K(KOF_NUCLEO_SLEEP), K(KOF_NUCLEO_SPAWN),
	K(KOF_NUCLEO_THREAD), K(KOF_NUCLEO_TIMESTOMP), K(KOF_NUCLEO_WRITE),
};
static const struct kc g065[] = {
	K(KOF_NUCLEO_ALLOC_EXEC),
};
static const struct kc g066[] = {
	K(KOF_NUCLEO_ANTI_DEBUG),
};
static const struct kc g067[] = {
	K(KOF_NUCLEO_CALL_REG),
};
static const struct kc g068[] = {
	K(KOF_NUCLEO_COPY_FROM_USER),
};
static const struct kc g069[] = {
	K(KOF_NUCLEO_COPY_TO_USER),
};
static const struct kc g070[] = {
	K(KOF_NUCLEO_CRED_PREPARE), K(KOF_NUCLEO_CRED_SET),
};
static const struct kc g071[] = {
	K(KOF_NUCLEO_EXEC_IMAGE), K(KOF_NUCLEO_EXEC_REG),
};
static const struct kc g072[] = {
	K(KOF_NUCLEO_FD_NONBLOCK), K(KOF_NUCLEO_FD_REDIR),
};
static const struct kc g073[] = {
	K(KOF_NUCLEO_FILE_DELETE), K(KOF_NUCLEO_FILE_OPEN), K(KOF_NUCLEO_FILE_RENAME),
};
static const struct kc g074[] = {
	K(KOF_NUCLEO_HTTP_CONNECT), K(KOF_NUCLEO_HTTP_FETCH), K(KOF_NUCLEO_HTTP_OPEN),
	K(KOF_NUCLEO_HTTP_RECV), K(KOF_NUCLEO_HTTP_SEND),
};
static const struct kc g075[] = {
	K(KOF_NUCLEO_KPROBE_REG), K(KOF_NUCLEO_KPROBE_UNREG),
};
static const struct kc g076[] = {
	K(KOF_NUCLEO_KSYM_LOOKUP),
};
static const struct kc g077[] = {
	K(KOF_NUCLEO_LIB_OPEN),
};
static const struct kc g078[] = {
	K(KOF_NUCLEO_LIST_HIDE),
};
static const struct kc g079[] = {
	K(KOF_NUCLEO_MEM_READ), K(KOF_NUCLEO_MEM_WRITE),
};
static const struct kc g080[] = {
	K(KOF_NUCLEO_MOD_LOAD),
};
static const struct kc g081[] = {
	K(KOF_NUCLEO_NAME_HASH),
};
static const struct kc g082[] = {
	K(KOF_NUCLEO_NET_ACCEPT), K(KOF_NUCLEO_NET_ADDR), K(KOF_NUCLEO_NET_BIND),
	K(KOF_NUCLEO_NET_CONNECT), K(KOF_NUCLEO_NET_HDRINCL), K(KOF_NUCLEO_NET_LISTEN),
	K(KOF_NUCLEO_NET_OPEN), K(KOF_NUCLEO_NET_RAW), K(KOF_NUCLEO_NET_READ),
	K(KOF_NUCLEO_NET_WRITE),
};
static const struct kc g083[] = {
	K(KOF_NUCLEO_PERM_SET),
};
static const struct kc g084[] = {
	K(KOF_NUCLEO_PIPE_OPEN),
};
static const struct kc g085[] = {
	K(KOF_NUCLEO_PROC_EXEC), K(KOF_NUCLEO_PROC_LIST), K(KOF_NUCLEO_PROC_MEM),
};
static const struct kc g086[] = {
	K(KOF_NUCLEO_PROT_OFF),
};
static const struct kc g087[] = {
	K(KOF_NUCLEO_REG_OPEN), K(KOF_NUCLEO_REG_SET),
};
static const struct kc g088[] = {
	K(KOF_NUCLEO_SELF_HIDE), K(KOF_NUCLEO_SELF_RESOLVE),
};
static const struct kc g089[] = {
	K(KOF_NUCLEO_SVC_INSTALL),
};
static const struct kc g090[] = {
	K(KOF_NUCLEO_SYMBOL_GET),
};
static const struct kc g091[] = {
};
static const struct kc g092[] = {
	K(KUNP_HDR_ELF32), K(KUNP_HDR_ELF64),
};
static const struct kc g093[] = {
	K(KUNP_PERM_R), K(KUNP_PERM_W), K(KUNP_PERM_X),
};
static const struct kc g094[] = {
	K(KOF_CURE_MASK_ADD8), K(KOF_CURE_MASK_NONE), K(KOF_CURE_MASK_ROL8),
	K(KOF_CURE_MASK_XOR16), K(KOF_CURE_MASK_XOR8),
};
static const struct kc g097[] = {
	K(KOF_DIAG_STR_MAX),
};
static const struct kc g098[] = {
	K(KDIG_ATTR_SYM), K(KDIG_ATTR_VALUE),
};
static const struct kc g099[] = {
	K(KDIG_SEC_DISEASE), K(KDIG_SEC_NEEDS), K(KDIG_SEC_REFS),
	K(KDIG_SEC_SEQUENCE), K(KDIG_SEC_USERS), K(KDIG_SEC_WHEN),
};
static const struct kc g100[] = {
	K(KOF_DIAG_ANALYSIS_APIHASH), K(KOF_DIAG_ANALYSIS_SYMBOL), K(KOF_DIAG_ANALYSIS_SYSCALL),
};
static const struct kc g101[] = {
	K(KOF_DIAG_B_FIELD_OF),
};
static const struct kc g102[] = {
	K(KOF_DIAG_B_PRODUCED), K(KOF_DIAG_B_SHARED), K(KOF_DIAG_B_VAL),
};
static const struct kc g104[] = {
	K(KOF_DIAG_MAX_NEED), K(KOF_DIAG_MAX_NODE), K(KOF_DIAG_MAX_WHEN),
};
static const struct kc g106[] = {
	K(KOF_DIAG_NO_PARENT),
};
static const struct kc g107[] = {
	K(KOF_DIAG_USES_EMU),
};
static const struct kc g108[] = {
	K(KOF_GR_FROM_NONE), K(KOF_GR_FROM_STACK),
};
static const struct kc g109[] = {
	K(KOF_GR_HDRLEN), K(KOF_GR_RECLEN),
};
static const struct kc g110[] = {
	K(KOF_GR_H_COUNT), K(KOF_GR_H_RESV),
};
static const struct kc g111[] = {
	K(KOF_GR_IN_FIT), K(KOF_GR_IN_MAX), K(KOF_GR_IN_STRIDE),
};
static const struct kc g112[] = {
	K(KOF_GR_R_AT), K(KOF_GR_R_ATTR), K(KOF_GR_R_BITS),
	K(KOF_GR_R_CAP), K(KOF_GR_R_FLAGS), K(KOF_GR_R_IN),
	K(KOF_GR_R_NIN),
};
static const struct kc g113[] = {
	K(KOF_ENT_F_CODED_UNKNOWN),
};
static const struct kc g114[] = {
	K(KOF_ENT_F_SCATTERED),
};
static const struct kc g115[] = {
	K(KOF_EMU_RGN_EXEC), K(KOF_EMU_RGN_IMAGE), K(KOF_EMU_RGN_WRITTEN),
};
static const struct kc g116[] = {
	K(KUNP_REG_AX), K(KUNP_REG_BP), K(KUNP_REG_BX),
	K(KUNP_REG_CX), K(KUNP_REG_DI), K(KUNP_REG_DX),
	K(KUNP_REG_IP), K(KUNP_REG_SI), K(KUNP_REG_SP),
};
static const struct kc g117[] = {
	K(KOF_MUTATION_MAX_HASH),
};
static const struct kc g118[] = {
	K(KOF_MUTATION_NAME_MAX),
};
static const struct kc g119[] = {
	K(KOF_MUTATION_RAW),
};
static const struct kc g120[] = {
};
static const struct kc g121[] = {
	K(KOF_NAME_MAX),
};
static const struct kc g122[] = {
	K(KOF_TARGET_COUNT),
};
static const struct kc g123[] = {
	K(KOF_TARGET_FIRST_EVENT),
};
static const struct kc g124[] = {
	K(KOF_TARGET_LIST_MAX),
};
static const struct kc g125[] = {
	K(KOF_SCAN_ALL), K(KOF_SCAN_EMBEDDED), K(KOF_SCAN_SYM),
};
static const struct kc g126[] = {
	K(KOF_SCAN_MAX_EXTENTS),
};
static const struct kc g127[] = {
	K(KOF_SCAN_SYM_EXP), K(KOF_SCAN_SYM_IMP),
};
static const struct kc g128[] = {
	K(KOF_LZMA_MAX_LC), K(KOF_LZMA_MAX_LP), K(KOF_LZMA_MAX_PB),
};
static const struct kc g129[] = {
	K(KOF_LZX_MAX_BITS),
};
static const struct kc g131[] = {
	K(KOF_SECF_CIPHERTEXT), K(KOF_SECF_CODE), K(KOF_SECF_DATA),
	K(KOF_SECF_HOLLOW), K(KOF_SECF_PAD), K(KOF_SECF_READ),
	K(KOF_SECF_REBUILT), K(KOF_SECF_SYNTHETIC),
};
static const struct kc g132[] = {
	K(KOF_XREF_ARG), K(KOF_XREF_CALL), K(KOF_XREF_JUMP),
	K(KOF_XREF_PARTIAL),
};
static const struct kc g133[] = {
};
static const struct kc g135[] = {
	K(KOF_SYM_HDRLEN), K(KOF_SYM_KEYLEN), K(KOF_SYM_MAGIC0),
	K(KOF_SYM_MAGIC1), K(KOF_SYM_MAGIC2), K(KOF_SYM_MAGIC3),
	K(KOF_SYM_RECLEN), K(KOF_SYM_VERSION),
};
static const struct kc g136[] = {
	K(KOF_SYM_H_COUNT), K(KOF_SYM_H_MAGIC), K(KOF_SYM_H_ORIGIN),
	K(KOF_SYM_H_RECLEN), K(KOF_SYM_H_START), K(KOF_SYM_H_TRUNC),
	K(KOF_SYM_H_VERSION),
};
static const struct kc g138[] = {
	K(KOF_SYM_NAME_MAX),
};
static const struct kc g139[] = {
	K(KOF_SYM_NO_START),
};
static const struct kc g141[] = {
	K(KOF_SYM_R_BIND), K(KOF_SYM_R_FLAGS), K(KOF_SYM_R_NAMECUT),
	K(KOF_SYM_R_NAMELEN), K(KOF_SYM_R_NAMEOFF), K(KOF_SYM_R_RESERVED),
	K(KOF_SYM_R_SHNDX), K(KOF_SYM_R_SIZE), K(KOF_SYM_R_TYPE),
	K(KOF_SYM_R_VALUE), K(KOF_SYM_R_VIS),
};
static const struct kc g142[] = {
	K(KOF_ENGINE_PATHOGEN),
};
static const struct kc g143[] = {
	K(KOF_LHA_ANOM_COUNT),
};
static const struct kc g144[] = {
	K(KOF_LHA_INFO_VERSION),
};
static const struct kc g146[] = {
	K(KOF_SCAN_LHA_CLAIMED),
};
static const struct kc g147[] = {
	K(KOF_LNK_ANOM_COUNT),
};
static const struct kc g149[] = {
	K(KOF_LNK_INFO_VERSION),
};
static const struct kc g150[] = {
	K(KOF_LNK_MAX_PARTS),
};
static const struct kc g151[] = {
	K(KOF_LNK_SIG_CONSOLE), K(KOF_LNK_SIG_DARWIN), K(KOF_LNK_SIG_ENV),
	K(KOF_LNK_SIG_ICONENV), K(KOF_LNK_SIG_KNOWNFLDR), K(KOF_LNK_SIG_PROPSTORE),
	K(KOF_LNK_SIG_SHIM), K(KOF_LNK_SIG_SPECIAL), K(KOF_LNK_SIG_TRACKER),
	K(KOF_LNK_SIG_VISTAIDL),
};
static const struct kc g152[] = {
	K(KOF_LNK_SIG_CONSOLE_FE),
};
static const struct kc g153[] = {
	K(KOF_SCAN_LNK_CLAIMED), K(KOF_SCAN_LNK_PARTS), K(KOF_SCAN_LNK_STRINGS),
};
static const struct kc g154[] = {
	K(KOF_PDF_ANOM_COUNT),
};
static const struct kc g156[] = {
	K(KOF_PDF_INFO_VERSION),
};
static const struct kc g158[] = {
	K(KOF_PDF_REGION_COUNT),
};
static const struct kc g159[] = {
	K(KOF_SCAN_PDF_CLAIMED),
};
static const struct kc g160[] = {
	K(KOF_PE_DIR_IAT), K(KOF_PE_DIR_IMPORT), K(KOF_PE_DIR_RESOURCE),
};
static const struct kc g161[] = {
	K(KOF_PE_DLL), K(KOF_PE_EXE), K(KOF_PE_SYS),
};
static const struct kc g162[] = {
	K(KOF_PE_MAX_SECTIONS),
};
static const struct kc g163[] = {
	K(KOF_PE_ORIGIN_DELETED), K(KOF_PE_ORIGIN_MANUAL),
};
static const struct kc g164[] = {
	K(KOF_PE_PERM_R), K(KOF_PE_PERM_W), K(KOF_PE_PERM_X),
};
static const struct kc g165[] = {
	K(KOF_PE_SECNAME_MAX),
};
static const struct kc g166[] = {
	K(KOF_SCAN_PE_CLAIMED), K(KOF_SCAN_PE_CODE), K(KOF_SCAN_PE_DATA),
	K(KOF_SCAN_PE_HEADERS), K(KOF_SCAN_PE_OVERLAY), K(KOF_SCAN_PE_RESOURCE),
	K(KOF_SCAN_PE_SIGNATURE), K(KOF_SCAN_PE_UNCLAIMED),
};
static const struct kc g167[] = {
};
static const struct kc g168[] = {
};
static const struct kc g170[] = {
	K(KOF_PROC_INFO_VERSION),
};
static const struct kc g171[] = {
	K(KOF_PROC_REC_MAGIC), K(KOF_PROC_REC_VERSION),
};
static const struct kc g172[] = {
	K(KOF_SCAN_PROC_CLAIMED),
};
static const struct kc g173[] = {
	K(KOF_RAR_ANOM_COUNT),
};
static const struct kc g174[] = {
	K(KOF_RAR_INFO_VERSION),
};
static const struct kc g176[] = {
	K(KOF_RAR_M_STORE),
};
static const struct kc g178[] = {
	K(KOF_SCAN_RAR_CLAIMED),
};
static const struct kc g179[] = {
	K(KOF_REG_ANOM_COUNT),
};
static const struct kc g181[] = {
	K(KOF_REG_INFO_VERSION),
};
static const struct kc g182[] = {
	K(KOF_REG_MAX_EXTENTS),
};
static const struct kc g183[] = {
	K(KOF_SCAN_REG_CLAIMED),
};
static const struct kc g184[] = {
	K(KOF_RTF_ANOM_COUNT),
};
static const struct kc g185[] = {
	K(KOF_RTF_CTRL_MAX),
};
static const struct kc g186[] = {
	K(KOF_RTF_INFO_VERSION),
};
static const struct kc g187[] = {
	K(KOF_RTF_MAX_DEPTH), K(KOF_RTF_MAX_EXTENTS), K(KOF_RTF_MAX_OBJECTS),
};
static const struct kc g188[] = {
	K(KOF_SCAN_RTF_BODY), K(KOF_SCAN_RTF_CLAIMED),
};
static const struct kc g189[] = {
	K(KOF_SCAN_SCRIPT_BODY), K(KOF_SCAN_SCRIPT_HEADER), K(KOF_SCAN_SCRIPT_MARKUP),
};
static const struct kc g190[] = {
	K(KOF_SCRIPT_ANOM_ISLANDS_FULL),
};
static const struct kc g191[] = {
	K(KOF_SCRIPT_MAX_ISLAND),
};
static const struct kc g192[] = {
	K(KOF_SFAM_CFM), K(KOF_SFAM_COUNT), K(KOF_SFAM_HTML),
	K(KOF_SFAM_NONE), K(KOF_SFAM_PHP), K(KOF_SFAM_SVR),
};
static const struct kc g193[] = {
	K(KOF_7Z_CODER_AES), K(KOF_7Z_CODER_BCJ2), K(KOF_7Z_CODER_COPY),
	K(KOF_7Z_CODER_LZMA), K(KOF_7Z_CODER_LZMA2),
};
static const struct kc g194[] = {
	K(KOF_7Z_CODER_BCJ_X86),
};
static const struct kc g195[] = {
	K(KOF_7Z_INFO_VERSION),
};
static const struct kc g198[] = {
	K(KOF_SCAN_7Z_CLAIMED),
};
static const struct kc g199[] = {
	K(KOF_SCAN_TAR_CLAIMED),
};
static const struct kc g200[] = {
	K(KOF_TAR_ANOM_COUNT),
};
static const struct kc g202[] = {
	K(KOF_TAR_INFO_VERSION),
};
static const struct kc g207[] = {
	K(KOF_SCAN_XZ_CLAIMED),
};
static const struct kc g208[] = {
	K(KOF_XZ_ANOM_COUNT),
};
static const struct kc g209[] = {
	K(KOF_XZ_FILTER_ARM), K(KOF_XZ_FILTER_ARMT), K(KOF_XZ_FILTER_DELTA),
	K(KOF_XZ_FILTER_IA64), K(KOF_XZ_FILTER_LZMA2), K(KOF_XZ_FILTER_PPC),
	K(KOF_XZ_FILTER_SPARC), K(KOF_XZ_FILTER_X86),
};
static const struct kc g212[] = {
	K(KOF_XZ_INFO_VERSION),
};
static const struct kc g216[] = {
	K(KOF_SCAN_ZIP_CLAIMED), K(KOF_SCAN_ZIP_CONTENT), K(KOF_SCAN_ZIP_STRUCT),
};
static const struct kc g217[] = {
	K(KOF_ZIP_ANOM_COUNT),
};
static const struct kc g219[] = {
	K(KOF_ZIP_INFO_VERSION),
};
static const struct kc g222[] = {
	K(KOF_LEVEL_HEUR), K(KOF_LEVEL_INFECT), K(KOF_LEVEL_SUSPECT),
};
static const struct kc g223[] = {
	K(KOFENG_MAJOR), K(KOFENG_MINOR),
};
static const struct kc g224[] = {
	K(KVERDICT_FILE_KIND), K(KVERDICT_FILE_NAME),
};

static const struct group groups[] = {
	{ "analyzers/diseases/msf_elf64.h: MSF_ELF64", g000, 2, 1 },
	{ "analyzers/diseases/msf_pe.h: MSF_PE", g001, 3, 1 },
	{ "detectors/linkage/kofdiag.h: KOF_DIAG_MATCH", g003, 3, 1 },
	{ "detectors/pattern/kofmatch.h: KOF_MEMO", g004, 4, 1 },
	{ "kofcore/kofcore.h: KOF_HASH", g008, 2, 1 },
	{ "kofcore/kofhash.h: KOF_ERR", g009, 3, 1 },
	{ "kofcore/kofmod/amsi.h: KOF_SCAN_AMSI", g010, 1, 2 },
	{ "kofcore/kofmod/arj.h: KOF_ARJ_ANOM", g011, 1, 2 },
	{ "kofcore/kofmod/arj.h: KOF_ARJ_INFO", g012, 1, 2 },
	{ "kofcore/kofmod/arj.h: KOF_SCAN_ARJ", g014, 1, 2 },
	{ "kofcore/kofmod/aspack_tab.h: kof_aspack", g017, 1, 2 },
	{ "kofcore/kofmod/bz2.h: KOF_BZ2_ANOM", g018, 1, 2 },
	{ "kofcore/kofmod/bz2.h: KOF_BZ2_INFO", g019, 1, 2 },
	{ "kofcore/kofmod/bz2.h: KOF_SCAN_BZ2", g020, 1, 2 },
	{ "kofcore/kofmod/cab.h: KOF_CAB_ANOM", g021, 1, 2 },
	{ "kofcore/kofmod/cab.h: KOF_CAB_INFO", g022, 1, 2 },
	{ "kofcore/kofmod/cab.h: KOF_CAB_MAX", g023, 1, 2 },
	{ "kofcore/kofmod/cab.h: KOF_SCAN_CAB", g024, 1, 2 },
	{ "kofcore/kofmod/cell.h: CELL", g025, 2, 1 },
	{ "kofcore/kofmod/cell.h: CELL_O", g026, 1, 2 },
	{ "kofcore/kofmod/cell.h: KOF_ARCH", g027, 21, 1 },
	{ "kofcore/kofmod/cell.h: KOF_ARCH_X86", g028, 1, 2 },
	{ "kofcore/kofmod/cell.h: KOF", g029, 2, 1 },
	{ "kofcore/kofmod/chm.h: KOF_CHM_ANOM", g030, 1, 2 },
	{ "kofcore/kofmod/chm.h: KOF_CHM_INFO", g031, 1, 2 },
	{ "kofcore/kofmod/chm.h: KOF_SCAN_CHM", g034, 1, 2 },
	{ "kofcore/kofmod/clr.h: KOF_SCAN_CLR", g035, 7, 1 },
	{ "kofcore/kofmod/docole.h: KOF_DOCOLE_ANOM", g036, 1, 2 },
	{ "kofcore/kofmod/docole.h: KOF_DOCOLE_INFO", g037, 1, 2 },
	{ "kofcore/kofmod/docole.h: KOF_DOCOLE_MAX", g039, 1, 2 },
	{ "kofcore/kofmod/docole.h: KOF_SCAN_DOCOLE", g042, 3, 1 },
	{ "kofcore/kofmod/elf.h: KOF_ELFDATA", g043, 1, 2 },
	{ "kofcore/kofmod/elf.h: KOF_ELF_ANOM_SECTAB", g044, 1, 2 },
	{ "kofcore/kofmod/elf.h: KOF_ELF_ANOM_SEC_PAST", g045, 1, 2 },
	{ "kofcore/kofmod/elf.h: KOF_ELF_ANOM_SHOFF_PAST", g046, 1, 2 },
	{ "kofcore/kofmod/elf.h: KOF_ELF", g047, 5, 1 },
	{ "kofcore/kofmod/elf.h: KOF_PERM", g049, 3, 0 },
	{ "kofcore/kofmod/elf.h: KOF_SCAN_ELF", g050, 6, 1 },
	{ "kofcore/kofmod/elf.h: KOF_SCAN_ELF_SLIB", g051, 2, 0 },
	{ "kofcore/kofmod/ep_shape.h: EPS", g053, 1, 2 },
	{ "kofcore/kofmod/gzip.h: KOF_GZIP_ANOM", g054, 1, 2 },
	{ "kofcore/kofmod/gzip.h: KOF_GZIP", g055, 1, 2 },
	{ "kofcore/kofmod/gzip.h: KOF_GZIP_INFO", g056, 1, 2 },
	{ "kofcore/kofmod/gzip.h: KOF_SCAN_GZIP", g058, 1, 2 },
	{ "kofcore/kofmod/heur.h: KOF_ENG_USE", g059, 1, 2 },
	{ "kofcore/kofmod/infected.h: KOF_INF", g060, 2, 1 },
	{ "kofcore/kofmod/kofabi.h: KOFSIG_ABI", g061, 2, 1 },
	{ "kofcore/kofmod/kofcap.h: KOF_FLOWF", g062, 1, 2 },
	{ "kofcore/kofmod/kofcap.h: KOF_NUCLEO_ACTION", g063, 2, 1 },
	{ "kofcore/kofmod/kofcap.h: KOF_NUCLEO", g064, 18, 1 },
	{ "kofcore/kofmod/kofcap.h: KOF_NUCLEO_ALLOC", g065, 1, 2 },
	{ "kofcore/kofmod/kofcap.h: KOF_NUCLEO_ANTI", g066, 1, 2 },
	{ "kofcore/kofmod/kofcap.h: KOF_NUCLEO_CALL", g067, 1, 2 },
	{ "kofcore/kofmod/kofcap.h: KOF_NUCLEO_COPY_FROM", g068, 1, 2 },
	{ "kofcore/kofmod/kofcap.h: KOF_NUCLEO_COPY_TO", g069, 1, 2 },
	{ "kofcore/kofmod/kofcap.h: KOF_NUCLEO_CRED", g070, 2, 1 },
	{ "kofcore/kofmod/kofcap.h: KOF_NUCLEO_EXEC", g071, 2, 1 },
	{ "kofcore/kofmod/kofcap.h: KOF_NUCLEO_FD", g072, 2, 1 },
	{ "kofcore/kofmod/kofcap.h: KOF_NUCLEO_FILE", g073, 3, 1 },
	{ "kofcore/kofmod/kofcap.h: KOF_NUCLEO_HTTP", g074, 5, 1 },
	{ "kofcore/kofmod/kofcap.h: KOF_NUCLEO_KPROBE", g075, 2, 1 },
	{ "kofcore/kofmod/kofcap.h: KOF_NUCLEO_KSYM", g076, 1, 2 },
	{ "kofcore/kofmod/kofcap.h: KOF_NUCLEO_LIB", g077, 1, 2 },
	{ "kofcore/kofmod/kofcap.h: KOF_NUCLEO_LIST", g078, 1, 2 },
	{ "kofcore/kofmod/kofcap.h: KOF_NUCLEO_MEM", g079, 2, 1 },
	{ "kofcore/kofmod/kofcap.h: KOF_NUCLEO_MOD", g080, 1, 2 },
	{ "kofcore/kofmod/kofcap.h: KOF_NUCLEO_NAME", g081, 1, 2 },
	{ "kofcore/kofmod/kofcap.h: KOF_NUCLEO_NET", g082, 10, 1 },
	{ "kofcore/kofmod/kofcap.h: KOF_NUCLEO_PERM", g083, 1, 2 },
	{ "kofcore/kofmod/kofcap.h: KOF_NUCLEO_PIPE", g084, 1, 2 },
	{ "kofcore/kofmod/kofcap.h: KOF_NUCLEO_PROC", g085, 3, 1 },
	{ "kofcore/kofmod/kofcap.h: KOF_NUCLEO_PROT", g086, 1, 2 },
	{ "kofcore/kofmod/kofcap.h: KOF_NUCLEO_REG", g087, 2, 1 },
	{ "kofcore/kofmod/kofcap.h: KOF_NUCLEO_SELF", g088, 2, 1 },
	{ "kofcore/kofmod/kofcap.h: KOF_NUCLEO_SVC", g089, 1, 2 },
	{ "kofcore/kofmod/kofcap.h: KOF_NUCLEO_SYMBOL", g090, 1, 2 },
	{ "kofcore/kofmod/kofcap.h: kof_flow_cap", g091, 1, 2 },
	{ "kofcore/kofmod/kofchild.h: KUNP_HDR", g092, 2, 1 },
	{ "kofcore/kofmod/kofchild.h: KUNP_PERM", g093, 3, 0 },
	{ "kofcore/kofmod/kofcure.h: KOF_CURE_MASK", g094, 5, 1 },
	{ "kofcore/kofmod/kofdiagnose.h: KOF_DIAG_STR", g097, 1, 2 },
	{ "kofcore/kofmod/kofdiagtree.h: KDIG_ATTR", g098, 2, 0 },
	{ "kofcore/kofmod/kofdiagtree.h: KDIG_SEC", g099, 6, 1 },
	{ "kofcore/kofmod/kofdiagtree.h: KOF_DIAG_ANALYSIS", g100, 3, 0 },
	{ "kofcore/kofmod/kofdiagtree.h: KOF_DIAG_B_FIELD", g101, 1, 2 },
	{ "kofcore/kofmod/kofdiagtree.h: KOF_DIAG_B", g102, 3, 0 },
	{ "kofcore/kofmod/kofdiagtree.h: KOF_DIAG_MAX", g104, 3, 2 },
	{ "kofcore/kofmod/kofdiagtree.h: KOF_DIAG_NO", g106, 1, 2 },
	{ "kofcore/kofmod/kofdiagtree.h: KOF_DIAG_USES", g107, 1, 2 },
	{ "kofcore/kofmod/kofdiagtree.h: KOF_GR_FROM", g108, 2, 1 },
	{ "kofcore/kofmod/kofdiagtree.h: KOF_GR", g109, 2, 0 },
	{ "kofcore/kofmod/kofdiagtree.h: KOF_GR_H", g110, 2, 1 },
	{ "kofcore/kofmod/kofdiagtree.h: KOF_GR_IN", g111, 3, 2 },
	{ "kofcore/kofmod/kofdiagtree.h: KOF_GR_R", g112, 7, 1 },
	{ "kofcore/kofmod/kofentry.h: KOF_ENT_F_CODED", g113, 1, 2 },
	{ "kofcore/kofmod/kofentry.h: KOF_ENT_F", g114, 1, 2 },
	{ "kofcore/kofmod/kofmodemu.h: KOF_EMU_RGN", g115, 3, 1 },
	{ "kofcore/kofmod/kofmodemu.h: KUNP_REG", g116, 9, 1 },
	{ "kofcore/kofmod/kofmutation.h: KOF_MUTATION_MAX", g117, 1, 2 },
	{ "kofcore/kofmod/kofmutation.h: KOF_MUTATION_NAME", g118, 1, 2 },
	{ "kofcore/kofmod/kofmutation.h: KOF_MUTATION", g119, 1, 2 },
	{ "kofcore/kofmod/kofmutation.h: kof_mutation", g120, 1, 2 },
	{ "kofcore/kofmod/kofname.h: KOF_NAME", g121, 1, 2 },
	{ "kofcore/kofmod/kofobjfmt.h: KOF_TARGET", g122, 1, 2 },
	{ "kofcore/kofmod/kofobjfmt.h: KOF_TARGET_FIRST", g123, 1, 2 },
	{ "kofcore/kofmod/kofobjfmt.h: KOF_TARGET_LIST", g124, 1, 2 },
	{ "kofcore/kofmod/kofregion.h: KOF_SCAN", g125, 3, 1 },
	{ "kofcore/kofmod/kofregion.h: KOF_SCAN_MAX", g126, 1, 2 },
	{ "kofcore/kofmod/kofregion.h: KOF_SCAN_SYM", g127, 2, 0 },
	{ "kofcore/kofmod/kofsig.h: KOF_LZMA_MAX", g128, 3, 2 },
	{ "kofcore/kofmod/kofsig.h: KOF_LZX_MAX", g129, 1, 2 },
	{ "kofcore/kofmod/kofsig.h: KOF_SECF", g131, 8, 1 },
	{ "kofcore/kofmod/kofsig.h: KOF_XREF", g132, 4, 0 },
	{ "kofcore/kofmod/kofsig.h: kof_xref", g133, 1, 2 },
	{ "kofcore/kofmod/kofsym.h: KOF_SYM", g135, 8, 2 },
	{ "kofcore/kofmod/kofsym.h: KOF_SYM_H", g136, 7, 1 },
	{ "kofcore/kofmod/kofsym.h: KOF_SYM_NAME", g138, 1, 2 },
	{ "kofcore/kofmod/kofsym.h: KOF_SYM_NO", g139, 1, 2 },
	{ "kofcore/kofmod/kofsym.h: KOF_SYM_R", g141, 11, 1 },
	{ "kofcore/kofmod/kofverdict.h: KOF_ENGINE", g142, 1, 2 },
	{ "kofcore/kofmod/lha.h: KOF_LHA_ANOM", g143, 1, 2 },
	{ "kofcore/kofmod/lha.h: KOF_LHA_INFO", g144, 1, 2 },
	{ "kofcore/kofmod/lha.h: KOF_SCAN_LHA", g146, 1, 2 },
	{ "kofcore/kofmod/lnk.h: KOF_LNK_ANOM", g147, 1, 2 },
	{ "kofcore/kofmod/lnk.h: KOF_LNK_INFO", g149, 1, 2 },
	{ "kofcore/kofmod/lnk.h: KOF_LNK_MAX", g150, 1, 2 },
	{ "kofcore/kofmod/lnk.h: KOF_LNK_SIG", g151, 10, 1 },
	{ "kofcore/kofmod/lnk.h: KOF_LNK_SIG_CONSOLE", g152, 1, 2 },
	{ "kofcore/kofmod/lnk.h: KOF_SCAN_LNK", g153, 3, 1 },
	{ "kofcore/kofmod/pdf.h: KOF_PDF_ANOM", g154, 1, 2 },
	{ "kofcore/kofmod/pdf.h: KOF_PDF_INFO", g156, 1, 2 },
	{ "kofcore/kofmod/pdf.h: KOF_PDF_REGION", g158, 1, 2 },
	{ "kofcore/kofmod/pdf.h: KOF_SCAN_PDF", g159, 1, 2 },
	{ "kofcore/kofmod/pe.h: KOF_PE_DIR", g160, 3, 1 },
	{ "kofcore/kofmod/pe.h: KOF_PE", g161, 3, 1 },
	{ "kofcore/kofmod/pe.h: KOF_PE_MAX", g162, 1, 2 },
	{ "kofcore/kofmod/pe.h: KOF_PE_ORIGIN", g163, 2, 0 },
	{ "kofcore/kofmod/pe.h: KOF_PE_PERM", g164, 3, 0 },
	{ "kofcore/kofmod/pe.h: KOF_PE_SECNAME", g165, 1, 2 },
	{ "kofcore/kofmod/pe.h: KOF_SCAN_PE", g166, 8, 1 },
	{ "kofcore/kofmod/pe.h: kof_pe_is", g167, 1, 2 },
	{ "kofcore/kofmod/pe.h: kof_pe_rva_to", g168, 1, 2 },
	{ "kofcore/kofmod/proc.h: KOF_PROC_INFO", g170, 1, 2 },
	{ "kofcore/kofmod/proc.h: KOF_PROC_REC", g171, 2, 1 },
	{ "kofcore/kofmod/proc.h: KOF_SCAN_PROC", g172, 1, 2 },
	{ "kofcore/kofmod/rar.h: KOF_RAR_ANOM", g173, 1, 2 },
	{ "kofcore/kofmod/rar.h: KOF_RAR_INFO", g174, 1, 2 },
	{ "kofcore/kofmod/rar.h: KOF_RAR_M", g176, 1, 2 },
	{ "kofcore/kofmod/rar.h: KOF_SCAN_RAR", g178, 1, 2 },
	{ "kofcore/kofmod/reg.h: KOF_REG_ANOM", g179, 1, 2 },
	{ "kofcore/kofmod/reg.h: KOF_REG_INFO", g181, 1, 2 },
	{ "kofcore/kofmod/reg.h: KOF_REG_MAX", g182, 1, 2 },
	{ "kofcore/kofmod/reg.h: KOF_SCAN_REG", g183, 1, 2 },
	{ "kofcore/kofmod/rtf.h: KOF_RTF_ANOM", g184, 1, 2 },
	{ "kofcore/kofmod/rtf.h: KOF_RTF_CTRL", g185, 1, 2 },
	{ "kofcore/kofmod/rtf.h: KOF_RTF_INFO", g186, 1, 2 },
	{ "kofcore/kofmod/rtf.h: KOF_RTF_MAX", g187, 3, 2 },
	{ "kofcore/kofmod/rtf.h: KOF_SCAN_RTF", g188, 2, 1 },
	{ "kofcore/kofmod/script.h: KOF_SCAN_SCRIPT", g189, 3, 0 },
	{ "kofcore/kofmod/script.h: KOF_SCRIPT_ANOM_ISLANDS", g190, 1, 2 },
	{ "kofcore/kofmod/script.h: KOF_SCRIPT_MAX", g191, 1, 2 },
	{ "kofcore/kofmod/script.h: KOF_SFAM", g192, 6, 1 },
	{ "kofcore/kofmod/sevenzip.h: KOF_7Z_CODER", g193, 5, 1 },
	{ "kofcore/kofmod/sevenzip.h: KOF_7Z_CODER_BCJ", g194, 1, 2 },
	{ "kofcore/kofmod/sevenzip.h: KOF_7Z_INFO", g195, 1, 2 },
	{ "kofcore/kofmod/sevenzip.h: KOF_SCAN_7Z", g198, 1, 2 },
	{ "kofcore/kofmod/tar.h: KOF_SCAN_TAR", g199, 1, 2 },
	{ "kofcore/kofmod/tar.h: KOF_TAR_ANOM", g200, 1, 2 },
	{ "kofcore/kofmod/tar.h: KOF_TAR_INFO", g202, 1, 2 },
	{ "kofcore/kofmod/xz.h: KOF_SCAN_XZ", g207, 1, 2 },
	{ "kofcore/kofmod/xz.h: KOF_XZ_ANOM", g208, 1, 2 },
	{ "kofcore/kofmod/xz.h: KOF_XZ_FILTER", g209, 8, 1 },
	{ "kofcore/kofmod/xz.h: KOF_XZ_INFO", g212, 1, 2 },
	{ "kofcore/kofmod/zip.h: KOF_SCAN_ZIP", g216, 3, 1 },
	{ "kofcore/kofmod/zip.h: KOF_ZIP_ANOM", g217, 1, 2 },
	{ "kofcore/kofmod/zip.h: KOF_ZIP_INFO", g219, 1, 2 },
	{ "kofcore/kofresult.h: KOF_LEVEL", g222, 3, 1 },
	{ "kofeng.h: KOFENG", g223, 2, 1 },
	{ "verdictor/verdict.h: KVERDICT_FILE", g224, 2, 1 },
};

/* the module ABI values this tree carries */
struct pin {
	const char *name;
	uint64_t    val, was;
};

static const struct pin pins[] = {
	{ "KOF_SCAN_AMSI_CLAIMED", (uint64_t)(KOF_SCAN_AMSI_CLAIMED), 6ull }, { "KOF_ARJ_INFO_VERSION", (uint64_t)(KOF_ARJ_INFO_VERSION), 2ull },
	{ "KOF_SCAN_ARJ_CLAIMED", (uint64_t)(KOF_SCAN_ARJ_CLAIMED), 14ull }, { "KOF_BZ2_INFO_VERSION", (uint64_t)(KOF_BZ2_INFO_VERSION), 1ull },
	{ "KOF_SCAN_BZ2_CLAIMED", (uint64_t)(KOF_SCAN_BZ2_CLAIMED), 6ull }, { "KOF_CAB_INFO_VERSION", (uint64_t)(KOF_CAB_INFO_VERSION), 2ull },
	{ "KOF_SCAN_CAB_CLAIMED", (uint64_t)(KOF_SCAN_CAB_CLAIMED), 30ull }, { "CELL_JMP", (uint64_t)(CELL_JMP), 34ull },
	{ "CELL_O_MEM", (uint64_t)(CELL_O_MEM), 2ull }, { "CELL_XOR", (uint64_t)(CELL_XOR), 15ull },
	{ "KOF_ARCH_ANY", (uint64_t)(KOF_ARCH_ANY), 0ull }, { "KOF_ARCH_ARC", (uint64_t)(KOF_ARCH_ARC), 11ull },
	{ "KOF_ARCH_ARM", (uint64_t)(KOF_ARCH_ARM), 3ull }, { "KOF_ARCH_ARM64", (uint64_t)(KOF_ARCH_ARM64), 4ull },
	{ "KOF_ARCH_CRIS", (uint64_t)(KOF_ARCH_CRIS), 18ull }, { "KOF_ARCH_M68K", (uint64_t)(KOF_ARCH_M68K), 13ull },
	{ "KOF_ARCH_MICROBLAZE", (uint64_t)(KOF_ARCH_MICROBLAZE), 16ull }, { "KOF_ARCH_MIPS", (uint64_t)(KOF_ARCH_MIPS), 6ull },
	{ "KOF_ARCH_MIPS64", (uint64_t)(KOF_ARCH_MIPS64), 8ull }, { "KOF_ARCH_OR1K", (uint64_t)(KOF_ARCH_OR1K), 19ull },
	{ "KOF_ARCH_OTHER", (uint64_t)(KOF_ARCH_OTHER), 255ull }, { "KOF_ARCH_PPC", (uint64_t)(KOF_ARCH_PPC), 9ull },
	{ "KOF_ARCH_PPC64", (uint64_t)(KOF_ARCH_PPC64), 7ull }, { "KOF_ARCH_RISCV32", (uint64_t)(KOF_ARCH_RISCV32), 10ull },
	{ "KOF_ARCH_RISCV64", (uint64_t)(KOF_ARCH_RISCV64), 5ull }, { "KOF_ARCH_SH", (uint64_t)(KOF_ARCH_SH), 12ull },
	{ "KOF_ARCH_SPARC", (uint64_t)(KOF_ARCH_SPARC), 14ull }, { "KOF_ARCH_SPARC64", (uint64_t)(KOF_ARCH_SPARC64), 15ull },
	{ "KOF_ARCH_X86", (uint64_t)(KOF_ARCH_X86), 1ull }, { "KOF_ARCH_X86_64", (uint64_t)(KOF_ARCH_X86_64), 2ull },
	{ "KOF_ARCH_XTENSA", (uint64_t)(KOF_ARCH_XTENSA), 17ull }, { "KOF_BROKEN", (uint64_t)(KOF_BROKEN), 18446744073709551614ull },
	{ "KOF_NA", (uint64_t)(KOF_NA), 18446744073709551615ull }, { "KOF_CHM_INFO_VERSION", (uint64_t)(KOF_CHM_INFO_VERSION), 2ull },
	{ "KOF_SCAN_CHM_CLAIMED", (uint64_t)(KOF_SCAN_CHM_CLAIMED), 14ull }, { "KOF_SCAN_CLR_BLOB", (uint64_t)(KOF_SCAN_CLR_BLOB), 4096ull },
	{ "KOF_SCAN_CLR_CLAIMED", (uint64_t)(KOF_SCAN_CLR_CLAIMED), 16128ull }, { "KOF_SCAN_CLR_HEADER", (uint64_t)(KOF_SCAN_CLR_HEADER), 256ull },
	{ "KOF_SCAN_CLR_RESOURCE", (uint64_t)(KOF_SCAN_CLR_RESOURCE), 8192ull }, { "KOF_SCAN_CLR_STRINGS", (uint64_t)(KOF_SCAN_CLR_STRINGS), 1024ull },
	{ "KOF_SCAN_CLR_TABLES", (uint64_t)(KOF_SCAN_CLR_TABLES), 512ull }, { "KOF_SCAN_CLR_US", (uint64_t)(KOF_SCAN_CLR_US), 2048ull },
	{ "KOF_DOCOLE_INFO_VERSION", (uint64_t)(KOF_DOCOLE_INFO_VERSION), 2ull }, 
	{ "KOF_SCAN_DOCOLE_CLAIMED", (uint64_t)(KOF_SCAN_DOCOLE_CLAIMED), 126ull },
	{ "KOF_SCAN_DOCOLE_CONTENT", (uint64_t)(KOF_SCAN_DOCOLE_CONTENT), 56ull }, { "KOF_SCAN_DOCOLE_STRUCT", (uint64_t)(KOF_SCAN_DOCOLE_STRUCT), 6ull },
	{ "KOF_ELFDATA_BE", (uint64_t)(KOF_ELFDATA_BE), 2ull }, { "KOF_ELF_ANOM_SECTAB_MISSING", (uint64_t)(KOF_ELF_ANOM_SECTAB_MISSING), 8388608ull },
	{ "KOF_ELF_ANOM_SEC_PAST_EOF", (uint64_t)(KOF_ELF_ANOM_SEC_PAST_EOF), 1048576ull }, { "KOF_ELF_ANOM_SHOFF_PAST_EOF", (uint64_t)(KOF_ELF_ANOM_SHOFF_PAST_EOF), 256ull },
	{ "KOF_ELF_CORE", (uint64_t)(KOF_ELF_CORE), 4ull }, { "KOF_ELF_DYN", (uint64_t)(KOF_ELF_DYN), 3ull },
	{ "KOF_ELF_EXEC", (uint64_t)(KOF_ELF_EXEC), 2ull }, { "KOF_ELF_NONE", (uint64_t)(KOF_ELF_NONE), 0ull },
	{ "KOF_ELF_REL", (uint64_t)(KOF_ELF_REL), 1ull }, { "KOF_PERM_R", (uint64_t)(KOF_PERM_R), 4ull },
	{ "KOF_PERM_W", (uint64_t)(KOF_PERM_W), 2ull }, { "KOF_PERM_X", (uint64_t)(KOF_PERM_X), 1ull },
	{ "KOF_SCAN_ELF_CLAIMED", (uint64_t)(KOF_SCAN_ELF_CLAIMED), 30ull }, { "KOF_SCAN_ELF_CODE", (uint64_t)(KOF_SCAN_ELF_CODE), 4ull },
	{ "KOF_SCAN_ELF_DATA", (uint64_t)(KOF_SCAN_ELF_DATA), 8ull }, { "KOF_SCAN_ELF_HEADERS", (uint64_t)(KOF_SCAN_ELF_HEADERS), 2ull },
	{ "KOF_SCAN_ELF_NOLOAD", (uint64_t)(KOF_SCAN_ELF_NOLOAD), 16ull }, { "KOF_SCAN_ELF_SLIB_CODE", (uint64_t)(KOF_SCAN_ELF_SLIB_CODE), 64ull },
	{ "KOF_SCAN_ELF_SLIB_DATA", (uint64_t)(KOF_SCAN_ELF_SLIB_DATA), 128ull }, { "KOF_SCAN_ELF_UNCLAIMED", (uint64_t)(KOF_SCAN_ELF_UNCLAIMED), 32ull },
	{ "KOF_GZIP_DEFLATE", (uint64_t)(KOF_GZIP_DEFLATE), 8ull }, { "KOF_GZIP_INFO_VERSION", (uint64_t)(KOF_GZIP_INFO_VERSION), 1ull },
	{ "KOF_SCAN_GZIP_CLAIMED", (uint64_t)(KOF_SCAN_GZIP_CLAIMED), 30ull }, { "KOF_ENG_USE_PATHOGEN", (uint64_t)(KOF_ENG_USE_PATHOGEN), 16ull },
	{ "KOF_INF_BODY", (uint64_t)(KOF_INF_BODY), 0ull }, { "KOF_INF_DAMAGE", (uint64_t)(KOF_INF_DAMAGE), 1ull },
	{ "KOFSIG_ABI_MIN", (uint64_t)(KOFSIG_ABI_MIN), 3ull }, { "KOFSIG_ABI_VERSION", (uint64_t)(KOFSIG_ABI_VERSION), 4ull },
	{ "KOF_FLOWF_WX", (uint64_t)(KOF_FLOWF_WX), 16ull }, { "KOF_NUCLEO_ACTION_READ", (uint64_t)(KOF_NUCLEO_ACTION_READ), 262ull },
	{ "KOF_NUCLEO_ACTION_WRITE", (uint64_t)(KOF_NUCLEO_ACTION_WRITE), 263ull }, { "KOF_NUCLEO_ALLOC", (uint64_t)(KOF_NUCLEO_ALLOC), 257ull },
	{ "KOF_NUCLEO_ALLOC_EXEC", (uint64_t)(KOF_NUCLEO_ALLOC_EXEC), 258ull }, { "KOF_NUCLEO_ANTI_DEBUG", (uint64_t)(KOF_NUCLEO_ANTI_DEBUG), 2ull },
	{ "KOF_NUCLEO_BACKGROUND", (uint64_t)(KOF_NUCLEO_BACKGROUND), 1283ull }, { "KOF_NUCLEO_CALL_REG", (uint64_t)(KOF_NUCLEO_CALL_REG), 1541ull },
	{ "KOF_NUCLEO_CAPTURE", (uint64_t)(KOF_NUCLEO_CAPTURE), 3073ull }, { "KOF_NUCLEO_COPY_FROM_USER", (uint64_t)(KOF_NUCLEO_COPY_FROM_USER), 2311ull },
	{ "KOF_NUCLEO_COPY_TO_USER", (uint64_t)(KOF_NUCLEO_COPY_TO_USER), 2312ull }, { "KOF_NUCLEO_CRED_PREPARE", (uint64_t)(KOF_NUCLEO_CRED_PREPARE), 2050ull },
	{ "KOF_NUCLEO_CRED_SET", (uint64_t)(KOF_NUCLEO_CRED_SET), 2049ull }, { "KOF_NUCLEO_CRYPTO", (uint64_t)(KOF_NUCLEO_CRYPTO), 2817ull },
	{ "KOF_NUCLEO_DNS", (uint64_t)(KOF_NUCLEO_DNS), 777ull }, { "KOF_NUCLEO_EXEC_IMAGE", (uint64_t)(KOF_NUCLEO_EXEC_IMAGE), 1281ull },
	{ "KOF_NUCLEO_EXEC_REG", (uint64_t)(KOF_NUCLEO_EXEC_REG), 260ull }, { "KOF_NUCLEO_FD_NONBLOCK", (uint64_t)(KOF_NUCLEO_FD_NONBLOCK), 4099ull },
	{ "KOF_NUCLEO_FD_REDIR", (uint64_t)(KOF_NUCLEO_FD_REDIR), 1289ull }, { "KOF_NUCLEO_FILE_DELETE", (uint64_t)(KOF_NUCLEO_FILE_DELETE), 516ull },
	{ "KOF_NUCLEO_FILE_OPEN", (uint64_t)(KOF_NUCLEO_FILE_OPEN), 513ull }, { "KOF_NUCLEO_FILE_RENAME", (uint64_t)(KOF_NUCLEO_FILE_RENAME), 517ull },
	{ "KOF_NUCLEO_HEAP", (uint64_t)(KOF_NUCLEO_HEAP), 259ull }, { "KOF_NUCLEO_HOOK", (uint64_t)(KOF_NUCLEO_HOOK), 2306ull },
	{ "KOF_NUCLEO_HTTP_CONNECT", (uint64_t)(KOF_NUCLEO_HTTP_CONNECT), 780ull }, { "KOF_NUCLEO_HTTP_FETCH", (uint64_t)(KOF_NUCLEO_HTTP_FETCH), 783ull },
	{ "KOF_NUCLEO_HTTP_OPEN", (uint64_t)(KOF_NUCLEO_HTTP_OPEN), 779ull }, { "KOF_NUCLEO_HTTP_RECV", (uint64_t)(KOF_NUCLEO_HTTP_RECV), 782ull },
	{ "KOF_NUCLEO_HTTP_SEND", (uint64_t)(KOF_NUCLEO_HTTP_SEND), 781ull }, { "KOF_NUCLEO_JAIL", (uint64_t)(KOF_NUCLEO_JAIL), 3329ull },
	{ "KOF_NUCLEO_KPROBE_REG", (uint64_t)(KOF_NUCLEO_KPROBE_REG), 2309ull }, { "KOF_NUCLEO_KPROBE_UNREG", (uint64_t)(KOF_NUCLEO_KPROBE_UNREG), 2310ull },
	{ "KOF_NUCLEO_KSYM_LOOKUP", (uint64_t)(KOF_NUCLEO_KSYM_LOOKUP), 2313ull }, { "KOF_NUCLEO_LIB_OPEN", (uint64_t)(KOF_NUCLEO_LIB_OPEN), 1537ull },
	{ "KOF_NUCLEO_LIST_HIDE", (uint64_t)(KOF_NUCLEO_LIST_HIDE), 2307ull }, { "KOF_NUCLEO_MEMFD", (uint64_t)(KOF_NUCLEO_MEMFD), 261ull },
	{ "KOF_NUCLEO_MEM_READ", (uint64_t)(KOF_NUCLEO_MEM_READ), 4097ull }, { "KOF_NUCLEO_MEM_WRITE", (uint64_t)(KOF_NUCLEO_MEM_WRITE), 4098ull },
	{ "KOF_NUCLEO_MOD_LOAD", (uint64_t)(KOF_NUCLEO_MOD_LOAD), 2305ull }, { "KOF_NUCLEO_NAME_HASH", (uint64_t)(KOF_NUCLEO_NAME_HASH), 1539ull },
	{ "KOF_NUCLEO_NET_ACCEPT", (uint64_t)(KOF_NUCLEO_NET_ACCEPT), 774ull }, { "KOF_NUCLEO_NET_ADDR", (uint64_t)(KOF_NUCLEO_NET_ADDR), 778ull },
	{ "KOF_NUCLEO_NET_BIND", (uint64_t)(KOF_NUCLEO_NET_BIND), 772ull }, { "KOF_NUCLEO_NET_CONNECT", (uint64_t)(KOF_NUCLEO_NET_CONNECT), 771ull },
	{ "KOF_NUCLEO_NET_HDRINCL", (uint64_t)(KOF_NUCLEO_NET_HDRINCL), 784ull }, { "KOF_NUCLEO_NET_LISTEN", (uint64_t)(KOF_NUCLEO_NET_LISTEN), 773ull },
	{ "KOF_NUCLEO_NET_OPEN", (uint64_t)(KOF_NUCLEO_NET_OPEN), 769ull }, { "KOF_NUCLEO_NET_RAW", (uint64_t)(KOF_NUCLEO_NET_RAW), 770ull },
	{ "KOF_NUCLEO_NET_READ", (uint64_t)(KOF_NUCLEO_NET_READ), 776ull }, { "KOF_NUCLEO_NET_WRITE", (uint64_t)(KOF_NUCLEO_NET_WRITE), 775ull },
	{ "KOF_NUCLEO_PERM_SET", (uint64_t)(KOF_NUCLEO_PERM_SET), 518ull }, { "KOF_NUCLEO_PIPE", (uint64_t)(KOF_NUCLEO_PIPE), 1026ull },
	{ "KOF_NUCLEO_PIPE_OPEN", (uint64_t)(KOF_NUCLEO_PIPE_OPEN), 1025ull }, { "KOF_NUCLEO_PROC_EXEC", (uint64_t)(KOF_NUCLEO_PROC_EXEC), 1287ull },
	{ "KOF_NUCLEO_PROC_MEM", (uint64_t)(KOF_NUCLEO_PROC_MEM), 1286ull }, { "KOF_NUCLEO_PROT_OFF", (uint64_t)(KOF_NUCLEO_PROT_OFF), 2308ull },
	{ "KOF_NUCLEO_PTRACE", (uint64_t)(KOF_NUCLEO_PTRACE), 1285ull }, { "KOF_NUCLEO_READ", (uint64_t)(KOF_NUCLEO_READ), 514ull },
	{ "KOF_NUCLEO_REG_OPEN", (uint64_t)(KOF_NUCLEO_REG_OPEN), 1793ull }, { "KOF_NUCLEO_REG_SET", (uint64_t)(KOF_NUCLEO_REG_SET), 1794ull },
	{ "KOF_NUCLEO_RESOLVE", (uint64_t)(KOF_NUCLEO_RESOLVE), 1538ull }, { "KOF_NUCLEO_SELF_HIDE", (uint64_t)(KOF_NUCLEO_SELF_HIDE), 1290ull },
	{ "KOF_NUCLEO_SELF_RESOLVE", (uint64_t)(KOF_NUCLEO_SELF_RESOLVE), 1540ull }, { "KOF_NUCLEO_SLEEP", (uint64_t)(KOF_NUCLEO_SLEEP), 1ull },
	{ "KOF_NUCLEO_SPAWN", (uint64_t)(KOF_NUCLEO_SPAWN), 1282ull }, { "KOF_NUCLEO_SVC_INSTALL", (uint64_t)(KOF_NUCLEO_SVC_INSTALL), 3585ull },
	{ "KOF_NUCLEO_SYMBOL_GET", (uint64_t)(KOF_NUCLEO_SYMBOL_GET), 2314ull }, { "KOF_NUCLEO_THREAD", (uint64_t)(KOF_NUCLEO_THREAD), 1288ull },
	{ "KOF_NUCLEO_TIMESTOMP", (uint64_t)(KOF_NUCLEO_TIMESTOMP), 519ull }, { "KOF_NUCLEO_WRITE", (uint64_t)(KOF_NUCLEO_WRITE), 515ull },
	{ "KUNP_HDR_ELF32", (uint64_t)(KUNP_HDR_ELF32), 84ull }, { "KUNP_HDR_ELF64", (uint64_t)(KUNP_HDR_ELF64), 120ull },
	{ "KUNP_PERM_R", (uint64_t)(KUNP_PERM_R), 4ull }, { "KUNP_PERM_W", (uint64_t)(KUNP_PERM_W), 2ull },
	{ "KUNP_PERM_X", (uint64_t)(KUNP_PERM_X), 1ull }, { "KOF_CURE_MASK_ADD8", (uint64_t)(KOF_CURE_MASK_ADD8), 3ull },
	{ "KOF_CURE_MASK_NONE", (uint64_t)(KOF_CURE_MASK_NONE), 0ull }, { "KOF_CURE_MASK_ROL8", (uint64_t)(KOF_CURE_MASK_ROL8), 4ull },
	{ "KOF_CURE_MASK_XOR16", (uint64_t)(KOF_CURE_MASK_XOR16), 2ull }, { "KOF_CURE_MASK_XOR8", (uint64_t)(KOF_CURE_MASK_XOR8), 1ull },
	{ "KDIG_ATTR_SYM", (uint64_t)(KDIG_ATTR_SYM), 2ull }, { "KDIG_ATTR_VALUE", (uint64_t)(KDIG_ATTR_VALUE), 1ull },
	{ "KDIG_SEC_DISEASE", (uint64_t)(KDIG_SEC_DISEASE), 8ull }, { "KDIG_SEC_NEEDS", (uint64_t)(KDIG_SEC_NEEDS), 6ull },
	{ "KDIG_SEC_REFS", (uint64_t)(KDIG_SEC_REFS), 4ull }, { "KDIG_SEC_SEQUENCE", (uint64_t)(KDIG_SEC_SEQUENCE), 7ull },
	{ "KDIG_SEC_USERS", (uint64_t)(KDIG_SEC_USERS), 3ull }, { "KDIG_SEC_WHEN", (uint64_t)(KDIG_SEC_WHEN), 2ull },
	{ "KOF_DIAG_ANALYSIS_APIHASH", (uint64_t)(KOF_DIAG_ANALYSIS_APIHASH), 8ull }, { "KOF_DIAG_ANALYSIS_SYMBOL", (uint64_t)(KOF_DIAG_ANALYSIS_SYMBOL), 2ull },
	{ "KOF_DIAG_ANALYSIS_SYSCALL", (uint64_t)(KOF_DIAG_ANALYSIS_SYSCALL), 1ull }, { "KOF_DIAG_B_FIELD_OF", (uint64_t)(KOF_DIAG_B_FIELD_OF), 16ull },
	{ "KOF_DIAG_B_PRODUCED", (uint64_t)(KOF_DIAG_B_PRODUCED), 2ull }, { "KOF_DIAG_B_SHARED", (uint64_t)(KOF_DIAG_B_SHARED), 4ull },
	{ "KOF_DIAG_B_VAL", (uint64_t)(KOF_DIAG_B_VAL), 8ull }, { "KOF_DIAG_NO_PARENT", (uint64_t)(KOF_DIAG_NO_PARENT), 255ull },
	{ "KOF_DIAG_USES_EMU", (uint64_t)(KOF_DIAG_USES_EMU), 4ull }, { "KOF_GR_FROM_NONE", (uint64_t)(KOF_GR_FROM_NONE), 65535ull },
	{ "KOF_GR_FROM_STACK", (uint64_t)(KOF_GR_FROM_STACK), 65534ull }, { "KOF_GR_HDRLEN", (uint64_t)(KOF_GR_HDRLEN), 8ull },
	{ "KOF_GR_H_RESV", (uint64_t)(KOF_GR_H_RESV), 4ull }, { "KOF_GR_RECLEN", (uint64_t)(KOF_GR_RECLEN), 32ull },
	{ "KOF_GR_R_AT", (uint64_t)(KOF_GR_R_AT), 0ull }, { "KOF_GR_R_ATTR", (uint64_t)(KOF_GR_R_ATTR), 8ull },
	{ "KOF_GR_R_BITS", (uint64_t)(KOF_GR_R_BITS), 20ull }, { "KOF_GR_R_CAP", (uint64_t)(KOF_GR_R_CAP), 16ull },
	{ "KOF_GR_R_FLAGS", (uint64_t)(KOF_GR_R_FLAGS), 18ull }, { "KOF_GR_R_IN", (uint64_t)(KOF_GR_R_IN), 22ull },
	{ "KOF_GR_R_NIN", (uint64_t)(KOF_GR_R_NIN), 21ull }, { "KOF_ENT_F_CODED_UNKNOWN", (uint64_t)(KOF_ENT_F_CODED_UNKNOWN), 2ull },
	{ "KOF_ENT_F_SCATTERED", (uint64_t)(KOF_ENT_F_SCATTERED), 1ull }, { "KOF_EMU_RGN_EXEC", (uint64_t)(KOF_EMU_RGN_EXEC), 1ull },
	{ "KOF_EMU_RGN_IMAGE", (uint64_t)(KOF_EMU_RGN_IMAGE), 0ull }, { "KOF_EMU_RGN_WRITTEN", (uint64_t)(KOF_EMU_RGN_WRITTEN), 2ull },
	{ "KUNP_REG_AX", (uint64_t)(KUNP_REG_AX), 0ull }, { "KUNP_REG_BP", (uint64_t)(KUNP_REG_BP), 5ull },
	{ "KUNP_REG_BX", (uint64_t)(KUNP_REG_BX), 3ull }, { "KUNP_REG_CX", (uint64_t)(KUNP_REG_CX), 1ull },
	{ "KUNP_REG_DI", (uint64_t)(KUNP_REG_DI), 7ull }, { "KUNP_REG_DX", (uint64_t)(KUNP_REG_DX), 2ull },
	{ "KUNP_REG_IP", (uint64_t)(KUNP_REG_IP), 16ull }, { "KUNP_REG_SI", (uint64_t)(KUNP_REG_SI), 6ull },
	{ "KUNP_REG_SP", (uint64_t)(KUNP_REG_SP), 4ull }, { "KOF_MUTATION_RAW", (uint64_t)(KOF_MUTATION_RAW), 0ull },
	{ "KOF_TARGET_FIRST_EVENT", (uint64_t)(KOF_TARGET_FIRST_EVENT), 19ull }, { "KOF_SCAN_ALL", (uint64_t)(KOF_SCAN_ALL), 1ull },
	{ "KOF_SCAN_EMBEDDED", (uint64_t)(KOF_SCAN_EMBEDDED), 536870912ull }, { "KOF_SCAN_SYM", (uint64_t)(KOF_SCAN_SYM), 3221225472ull },
	{ "KOF_SCAN_SYM_EXP", (uint64_t)(KOF_SCAN_SYM_EXP), 2147483648ull }, { "KOF_SCAN_SYM_IMP", (uint64_t)(KOF_SCAN_SYM_IMP), 1073741824ull },
	{ "KOF_SECF_CIPHERTEXT", (uint64_t)(KOF_SECF_CIPHERTEXT), 128ull }, { "KOF_SECF_CODE", (uint64_t)(KOF_SECF_CODE), 1ull },
	{ "KOF_SECF_DATA", (uint64_t)(KOF_SECF_DATA), 2ull }, { "KOF_SECF_HOLLOW", (uint64_t)(KOF_SECF_HOLLOW), 8ull },
	{ "KOF_SECF_PAD", (uint64_t)(KOF_SECF_PAD), 4ull }, { "KOF_SECF_READ", (uint64_t)(KOF_SECF_READ), 0ull },
	{ "KOF_SECF_REBUILT", (uint64_t)(KOF_SECF_REBUILT), 16ull }, { "KOF_SECF_SYNTHETIC", (uint64_t)(KOF_SECF_SYNTHETIC), 32ull },
	{ "KOF_XREF_ARG", (uint64_t)(KOF_XREF_ARG), 16ull }, { "KOF_XREF_CALL", (uint64_t)(KOF_XREF_CALL), 4ull },
	{ "KOF_XREF_JUMP", (uint64_t)(KOF_XREF_JUMP), 8ull }, { "KOF_XREF_PARTIAL", (uint64_t)(KOF_XREF_PARTIAL), 32ull },
	{ "KOF_SYM_HDRLEN", (uint64_t)(KOF_SYM_HDRLEN), 16ull }, { "KOF_SYM_H_MAGIC", (uint64_t)(KOF_SYM_H_MAGIC), 0ull },
	{ "KOF_SYM_H_ORIGIN", (uint64_t)(KOF_SYM_H_ORIGIN), 12ull }, { "KOF_SYM_H_RECLEN", (uint64_t)(KOF_SYM_H_RECLEN), 6ull },
	{ "KOF_SYM_H_START", (uint64_t)(KOF_SYM_H_START), 14ull }, { "KOF_SYM_H_TRUNC", (uint64_t)(KOF_SYM_H_TRUNC), 13ull },
	{ "KOF_SYM_H_VERSION", (uint64_t)(KOF_SYM_H_VERSION), 4ull }, { "KOF_SYM_KEYLEN", (uint64_t)(KOF_SYM_KEYLEN), 4ull },
	{ "KOF_SYM_MAGIC0", (uint64_t)(KOF_SYM_MAGIC0), 75ull }, { "KOF_SYM_MAGIC1", (uint64_t)(KOF_SYM_MAGIC1), 83ull },
	{ "KOF_SYM_MAGIC2", (uint64_t)(KOF_SYM_MAGIC2), 89ull }, { "KOF_SYM_MAGIC3", (uint64_t)(KOF_SYM_MAGIC3), 77ull },
	{ "KOF_SYM_NO_START", (uint64_t)(KOF_SYM_NO_START), 65535ull }, { "KOF_SYM_RECLEN", (uint64_t)(KOF_SYM_RECLEN), 32ull },
	{ "KOF_SYM_R_BIND", (uint64_t)(KOF_SYM_R_BIND), 1ull }, { "KOF_SYM_R_FLAGS", (uint64_t)(KOF_SYM_R_FLAGS), 3ull },
	{ "KOF_SYM_R_NAMECUT", (uint64_t)(KOF_SYM_R_NAMECUT), 12ull }, { "KOF_SYM_R_NAMELEN", (uint64_t)(KOF_SYM_R_NAMELEN), 8ull },
	{ "KOF_SYM_R_NAMEOFF", (uint64_t)(KOF_SYM_R_NAMEOFF), 4ull }, { "KOF_SYM_R_RESERVED", (uint64_t)(KOF_SYM_R_RESERVED), 13ull },
	{ "KOF_SYM_R_SHNDX", (uint64_t)(KOF_SYM_R_SHNDX), 10ull }, { "KOF_SYM_R_SIZE", (uint64_t)(KOF_SYM_R_SIZE), 16ull },
	{ "KOF_SYM_R_TYPE", (uint64_t)(KOF_SYM_R_TYPE), 0ull }, { "KOF_SYM_R_VALUE", (uint64_t)(KOF_SYM_R_VALUE), 24ull },
	{ "KOF_SYM_R_VIS", (uint64_t)(KOF_SYM_R_VIS), 2ull }, { "KOF_SYM_VERSION", (uint64_t)(KOF_SYM_VERSION), 4ull },
	{ "KOF_ENGINE_PATHOGEN", (uint64_t)(KOF_ENGINE_PATHOGEN), 4ull }, { "KOF_LHA_INFO_VERSION", (uint64_t)(KOF_LHA_INFO_VERSION), 2ull },
	{ "KOF_SCAN_LHA_CLAIMED", (uint64_t)(KOF_SCAN_LHA_CLAIMED), 14ull }, { "KOF_LNK_INFO_VERSION", (uint64_t)(KOF_LNK_INFO_VERSION), 2ull },
	{ "KOF_LNK_SIG_CONSOLE", (uint64_t)(KOF_LNK_SIG_CONSOLE), 2684354562ull }, { "KOF_LNK_SIG_CONSOLE_FE", (uint64_t)(KOF_LNK_SIG_CONSOLE_FE), 2684354564ull },
	{ "KOF_LNK_SIG_DARWIN", (uint64_t)(KOF_LNK_SIG_DARWIN), 2684354566ull }, { "KOF_LNK_SIG_ENV", (uint64_t)(KOF_LNK_SIG_ENV), 2684354561ull },
	{ "KOF_LNK_SIG_ICONENV", (uint64_t)(KOF_LNK_SIG_ICONENV), 2684354567ull }, { "KOF_LNK_SIG_KNOWNFLDR", (uint64_t)(KOF_LNK_SIG_KNOWNFLDR), 2684354571ull },
	{ "KOF_LNK_SIG_PROPSTORE", (uint64_t)(KOF_LNK_SIG_PROPSTORE), 2684354569ull }, { "KOF_LNK_SIG_SHIM", (uint64_t)(KOF_LNK_SIG_SHIM), 2684354568ull },
	{ "KOF_LNK_SIG_SPECIAL", (uint64_t)(KOF_LNK_SIG_SPECIAL), 2684354565ull }, { "KOF_LNK_SIG_TRACKER", (uint64_t)(KOF_LNK_SIG_TRACKER), 2684354563ull },
	{ "KOF_LNK_SIG_VISTAIDL", (uint64_t)(KOF_LNK_SIG_VISTAIDL), 2684354572ull }, { "KOF_SCAN_LNK_CLAIMED", (uint64_t)(KOF_SCAN_LNK_CLAIMED), 130046ull },
	{ "KOF_SCAN_LNK_PARTS", (uint64_t)(KOF_SCAN_LNK_PARTS), 129544ull }, { "KOF_SCAN_LNK_STRINGS", (uint64_t)(KOF_SCAN_LNK_STRINGS), 496ull },
	{ "KOF_PDF_INFO_VERSION", (uint64_t)(KOF_PDF_INFO_VERSION), 2ull }, { "KOF_SCAN_PDF_CLAIMED", (uint64_t)(KOF_SCAN_PDF_CLAIMED), 536871422ull },
	{ "KOF_PE_DIR_IAT", (uint64_t)(KOF_PE_DIR_IAT), 12ull }, { "KOF_PE_DIR_IMPORT", (uint64_t)(KOF_PE_DIR_IMPORT), 1ull },
	{ "KOF_PE_DIR_RESOURCE", (uint64_t)(KOF_PE_DIR_RESOURCE), 2ull }, { "KOF_PE_DLL", (uint64_t)(KOF_PE_DLL), 1ull },
	{ "KOF_PE_EXE", (uint64_t)(KOF_PE_EXE), 0ull }, { "KOF_PE_ORIGIN_DELETED", (uint64_t)(KOF_PE_ORIGIN_DELETED), 2ull },
	{ "KOF_PE_ORIGIN_MANUAL", (uint64_t)(KOF_PE_ORIGIN_MANUAL), 1ull }, { "KOF_PE_PERM_R", (uint64_t)(KOF_PE_PERM_R), 4ull },
	{ "KOF_PE_PERM_W", (uint64_t)(KOF_PE_PERM_W), 2ull }, { "KOF_PE_PERM_X", (uint64_t)(KOF_PE_PERM_X), 1ull },
	{ "KOF_PE_SYS", (uint64_t)(KOF_PE_SYS), 2ull }, { "KOF_SCAN_PE_CLAIMED", (uint64_t)(KOF_SCAN_PE_CLAIMED), 16318ull },
	{ "KOF_SCAN_PE_CODE", (uint64_t)(KOF_SCAN_PE_CODE), 4ull }, { "KOF_SCAN_PE_DATA", (uint64_t)(KOF_SCAN_PE_DATA), 8ull },
	{ "KOF_SCAN_PE_HEADERS", (uint64_t)(KOF_SCAN_PE_HEADERS), 2ull }, { "KOF_SCAN_PE_OVERLAY", (uint64_t)(KOF_SCAN_PE_OVERLAY), 32ull },
	{ "KOF_SCAN_PE_RESOURCE", (uint64_t)(KOF_SCAN_PE_RESOURCE), 128ull }, { "KOF_SCAN_PE_SIGNATURE", (uint64_t)(KOF_SCAN_PE_SIGNATURE), 16ull },
	{ "KOF_SCAN_PE_UNCLAIMED", (uint64_t)(KOF_SCAN_PE_UNCLAIMED), 64ull }, { "KOF_PROC_INFO_VERSION", (uint64_t)(KOF_PROC_INFO_VERSION), 1ull },
	{ "KOF_PROC_REC_MAGIC", (uint64_t)(KOF_PROC_REC_MAGIC), 1129271888ull }, { "KOF_PROC_REC_VERSION", (uint64_t)(KOF_PROC_REC_VERSION), 3ull },
	{ "KOF_SCAN_PROC_CLAIMED", (uint64_t)(KOF_SCAN_PROC_CLAIMED), 52ull }, { "KOF_RAR_INFO_VERSION", (uint64_t)(KOF_RAR_INFO_VERSION), 2ull },
	{ "KOF_RAR_M_STORE", (uint64_t)(KOF_RAR_M_STORE), 48ull }, { "KOF_SCAN_RAR_CLAIMED", (uint64_t)(KOF_SCAN_RAR_CLAIMED), 30ull },
	{ "KOF_REG_INFO_VERSION", (uint64_t)(KOF_REG_INFO_VERSION), 1ull }, { "KOF_SCAN_REG_CLAIMED", (uint64_t)(KOF_SCAN_REG_CLAIMED), 62ull },
	{ "KOF_RTF_INFO_VERSION", (uint64_t)(KOF_RTF_INFO_VERSION), 1ull }, { "KOF_SCAN_RTF_BODY", (uint64_t)(KOF_SCAN_RTF_BODY), 2ull },
	{ "KOF_SCAN_RTF_CLAIMED", (uint64_t)(KOF_SCAN_RTF_CLAIMED), 14ull }, { "KOF_SCAN_SCRIPT_BODY", (uint64_t)(KOF_SCAN_SCRIPT_BODY), 4ull },
	{ "KOF_SCAN_SCRIPT_HEADER", (uint64_t)(KOF_SCAN_SCRIPT_HEADER), 2ull }, { "KOF_SCAN_SCRIPT_MARKUP", (uint64_t)(KOF_SCAN_SCRIPT_MARKUP), 8ull },
	{ "KOF_SCRIPT_ANOM_ISLANDS_FULL", (uint64_t)(KOF_SCRIPT_ANOM_ISLANDS_FULL), 1ull }, { "KOF_SFAM_CFM", (uint64_t)(KOF_SFAM_CFM), 3ull },
	{ "KOF_SFAM_HTML", (uint64_t)(KOF_SFAM_HTML), 4ull }, { "KOF_SFAM_NONE", (uint64_t)(KOF_SFAM_NONE), 0ull },
	{ "KOF_SFAM_PHP", (uint64_t)(KOF_SFAM_PHP), 1ull }, { "KOF_SFAM_SVR", (uint64_t)(KOF_SFAM_SVR), 2ull },
	{ "KOF_7Z_CODER_AES", (uint64_t)(KOF_7Z_CODER_AES), 116459265ull }, { "KOF_7Z_CODER_BCJ2", (uint64_t)(KOF_7Z_CODER_BCJ2), 50528539ull },
	{ "KOF_7Z_CODER_BCJ_X86", (uint64_t)(KOF_7Z_CODER_BCJ_X86), 50528515ull }, { "KOF_7Z_CODER_COPY", (uint64_t)(KOF_7Z_CODER_COPY), 0ull },
	{ "KOF_7Z_CODER_LZMA", (uint64_t)(KOF_7Z_CODER_LZMA), 196865ull }, { "KOF_7Z_CODER_LZMA2", (uint64_t)(KOF_7Z_CODER_LZMA2), 33ull },
	{ "KOF_7Z_INFO_VERSION", (uint64_t)(KOF_7Z_INFO_VERSION), 2ull }, { "KOF_SCAN_7Z_CLAIMED", (uint64_t)(KOF_SCAN_7Z_CLAIMED), 6ull },
	{ "KOF_SCAN_TAR_CLAIMED", (uint64_t)(KOF_SCAN_TAR_CLAIMED), 6ull }, { "KOF_TAR_INFO_VERSION", (uint64_t)(KOF_TAR_INFO_VERSION), 2ull },
	{ "KOF_SCAN_XZ_CLAIMED", (uint64_t)(KOF_SCAN_XZ_CLAIMED), 6ull }, { "KOF_XZ_FILTER_ARM", (uint64_t)(KOF_XZ_FILTER_ARM), 7ull },
	{ "KOF_XZ_FILTER_ARMT", (uint64_t)(KOF_XZ_FILTER_ARMT), 8ull }, { "KOF_XZ_FILTER_DELTA", (uint64_t)(KOF_XZ_FILTER_DELTA), 3ull },
	{ "KOF_XZ_FILTER_IA64", (uint64_t)(KOF_XZ_FILTER_IA64), 6ull }, { "KOF_XZ_FILTER_LZMA2", (uint64_t)(KOF_XZ_FILTER_LZMA2), 33ull },
	{ "KOF_XZ_FILTER_PPC", (uint64_t)(KOF_XZ_FILTER_PPC), 5ull }, { "KOF_XZ_FILTER_SPARC", (uint64_t)(KOF_XZ_FILTER_SPARC), 9ull },
	{ "KOF_XZ_FILTER_X86", (uint64_t)(KOF_XZ_FILTER_X86), 4ull }, { "KOF_XZ_INFO_VERSION", (uint64_t)(KOF_XZ_INFO_VERSION), 1ull },
	{ "KOF_SCAN_ZIP_CLAIMED", (uint64_t)(KOF_SCAN_ZIP_CLAIMED), 30ull }, { "KOF_SCAN_ZIP_CONTENT", (uint64_t)(KOF_SCAN_ZIP_CONTENT), 24ull },
	{ "KOF_SCAN_ZIP_STRUCT", (uint64_t)(KOF_SCAN_ZIP_STRUCT), 6ull }, { "KOF_ZIP_INFO_VERSION", (uint64_t)(KOF_ZIP_INFO_VERSION), 2ull },
	{ "KOF_HASH_INIT", (uint64_t)(KOF_HASH_INIT), 2166136261ull }, { "KOF_HASH_PRIME", (uint64_t)(KOF_HASH_PRIME), 16777619ull },
	{ "KOF_GR_H_COUNT", (uint64_t)(KOF_GR_H_COUNT), 0ull }, { "KOF_GR_IN_STRIDE", (uint64_t)(KOF_GR_IN_STRIDE), 4ull },
	{ "KOF_GR_IN_MAX", (uint64_t)(KOF_GR_IN_MAX), 4ull }, { "KOF_GR_IN_FIT", (uint64_t)(KOF_GR_IN_FIT), 2ull },
};

static unsigned pop64(uint64_t v)
{
	unsigned n = 0;

	for (; v; v &= v - 1u)
		n++;
	return n;
}

static void t_groups(void)
{
	unsigned g, i, j;

	for (g = 0; g < sizeof groups / sizeof groups[0]; g++) {
		const struct group *gr = &groups[g];

		for (i = 0; i < gr->n; i++) {
			if (gr->kind == 0)
				CK(pop64(gr->m[i].val) == 1, "%s: %s = %#llx is not a single bit", gr->what, gr->m[i].name,
				   (unsigned long long)gr->m[i].val);
			for (j = i + 1; j < gr->n && gr->kind <= 1; j++)
				CK(gr->m[i].val != gr->m[j].val, "%s: %s and %s are both %#llx", gr->what, gr->m[i].name,
				   gr->m[j].name, (unsigned long long)gr->m[i].val);
		}
	}
}


/* The pins are the values of the module ABI. They were read from the headers at
 * the ABI this tree carries (KOFSIG_ABI_VERSION), so this table is a statement that
 * nothing under kofcore/ moved without the version moving with it. */
static void t_pins(void)
{
	unsigned i;

	for (i = 0; i < sizeof pins / sizeof pins[0]; i++)
		CK(pins[i].val == pins[i].was, "%s is %llu, this ABI had %llu", pins[i].name,
		   (unsigned long long)pins[i].val, (unsigned long long)pins[i].was);
	CK(sizeof pins / sizeof pins[0] > 100, "the pin table is not empty");
}

int main(void)
{
	t_groups();
	t_pins();
	printf("api_engine_constants: %u checks, %u failed, %u known-miss\n", he_checks, he_fails, km_known());
	return he_fails != 0 || km_failed();
}
