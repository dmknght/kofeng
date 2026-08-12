#include <kofmod/kofsig.h>
#include <kofmod/elf.h>

/*
    Target is Linux Rootkit. Binary is ELF REL. Use that to filter target
*/
KOF_TARGET_FORMAT(KOF_FMT_ELF);
KOF_TARGET_SUBTYPE(KOF_ELF_REL);

/*
    Data is exposed in KOF_SCAN_ELF_DATA. These are symbols that the rootkit uses to start hooking syscalls (particularly on x64).
    If target is cross platform, other strings are required (arm64_syscall_table?)
    Regarding architecture specific, ARM64 has "update_mapping_prot" "__start_rodata" and ""__init_begin"
            #elif IS_ENABLED(CONFIG_ARM64)
            update_mapping_prot = (void *)findmyinterest("update_mapping_prot");
            start_rodata = (unsigned long)findmyinterest("__start_rodata");
            init_begin = (unsigned long)findmyinterest("__init_begin");
        #endif
    Meanwhile X86 calls
        	asm volatile(
            "mov %0, %%cr0"
            : "+r"(val), "+m"(__force_order));
    But X64 calls x64_sys_call
        #if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 9, 0) && (IS_ENABLED(CONFIG_X86) || IS_ENABLED(CONFIG_X86_64))
            sys_call = (t_syscall)findmyinterest("x64_sys_call");
            if (!sys_call)
                return -1;
*/
KOF_TARGET_RANGE(scan_elf_data, KOF_SCAN_ELF_DATA);

KOF_DEFINE_STR(str_1, "kallsyms_lookup_name", KOF_CASE_EXACT, KOF_WORD_FULLWORD);
KOF_DEFINE_STR(str_2, "sys_call_table", KOF_CASE_EXACT, KOF_WORD_FULLWORD);
KOF_DEFINE_STR(str_x64, "x64_sys_call", KOF_CASE_EXACT, KOF_WORD_FULLWORD);
KOF_DEFINE_STR(str_a64_1, "update_mapping_prot", KOF_CASE_EXACT, KOF_WORD_FULLWORD);
KOF_DEFINE_STR(str_a64_2, "__start_rodata", KOF_CASE_EXACT, KOF_WORD_FULLWORD);


KOF_DEFINE_SCAN
{
	/*
	 * A threshold, written as one. Each call answers how many of the listed
	 * strings are present - distinct strings, not occurrences, so a file that
	 * repeats one marker forty times still counts one.
	 *
	 * None of the calls holds pattern bytes: the host owns the literals and
	 * answers these, so every marker here is looked for in one pass over the
	 * object, together with every other module's.
	 */
	if (kof_find_str_all(scan_elf_data, str_1, str_2))
    {
        if (kof_find_str_all(scan_elf_data, str_x64))
        {
            KOF_SCAN_MATCH("Rootkit.Diamorphine-x64", KOF_LVL_INFECT);
        }

        if (kof_find_str_all(scan_elf_data, str_a64_1, str_a64_2))
        {
            KOF_SCAN_MATCH("Rootkit.Diamorphine-a64", KOF_LVL_INFECT);
        } 
    }
		
}
