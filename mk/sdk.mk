# ------------------------------------------------------------------- the SDK
#
# Two public surfaces with different audiences, kept apart by path rather than by
# a note asking people to be careful:
#
#   <kofeng.h>            a host that wants to scan things
#   <kofmod/kofsig.h>     a signature module, which is a different ABI entirely
#
# Everything else under libkofeng is internal and is deliberately absent here, so
# reaching for it is a compile error rather than a habit. That is the constraint
# kofscanner is already built under, applied to anyone outside this tree.

SDK_HDR := $(SDK)/include/kofeng.h \
           $(SDK)/include/koftypes.h \
           $(SDK)/include/kofobjname.h \
           $(SDK)/include/kofresult.h \
           $(SDK)/include/kofoption.h \
           $(SDK)/include/kofcore.h \
           $(SDK)/include/kofplatform.h \
           $(SDK)/include/kofplatform_os.h \
           $(SDK)/include/kofplatform_file.h \
           $(SDK)/include/kofdebug.h \
           $(SDK)/include/kofhash.h \
           $(SDK)/include/kofentropy.h \
           $(SDK)/include/verdictor/verdict.h \
           $(SDK)/include/verdictor/famcat.h \
           $(SDK)/include/kofmod/kofsig.h \
           $(SDK)/include/kofmod/kofabi.h \
           $(SDK)/include/kofmod/kofobjfmt.h \
           $(SDK)/include/kofmod/kofname.h \
           $(SDK)/include/kofmod/kofregion.h \
           $(SDK)/include/kofmod/kofcontent.h \
           $(SDK)/include/kofmod/kofentry.h \
           $(SDK)/include/kofmod/kofctx.h \
           $(SDK)/include/kofmod/kofdefine.h \
           $(SDK)/include/kofmod/kofsearch.h \
           $(SDK)/include/kofmod/kofmeasure.h \
           $(SDK)/include/kofmod/kofdiagnose.h \
           $(SDK)/include/kofmod/kofread.h \
           $(SDK)/include/kofmod/kofchild.h \
           $(SDK)/include/kofmod/kofmodemu.h \
           $(SDK)/include/kofmod/kofverdict.h \
           $(SDK)/include/kofmod/kofdeclare.h \
           $(SDK)/include/kofmod/kofhit.h \
           $(SDK)/include/kofmod/basic.h \
           $(SDK)/include/kofmod/cell.h \
           $(SDK)/include/kofmod/infected.h \
           $(SDK)/include/kofmod/kofmutation.h \
           $(SDK)/include/kofmod/kofcap.h \
           $(SDK)/include/kofmod/kofsym.h \
           $(SDK)/include/kofmod/kofdiagtree.h \
           $(SDK)/include/kofmod/disease.h \
           $(SDK)/include/kofmod/kofdecode.h \
           $(SDK)/include/kofmod/aspack_tab.h \
           $(SDK)/include/kofmod/elf.h \
           $(SDK)/include/kofmod/pe.h \
           $(SDK)/include/kofmod/gzip.h \
           $(SDK)/include/kofmod/docole.h \
           $(SDK)/include/kofmod/zip.h \
           $(SDK)/include/kofmod/tar.h \
           $(SDK)/include/kofmod/sevenzip.h \
           $(SDK)/include/kofmod/rar.h \
           $(SDK)/include/kofmod/xz.h \
           $(SDK)/include/kofmod/bz2.h \
           $(SDK)/include/kofmod/chm.h \
           $(SDK)/include/kofmod/cab.h \
           $(SDK)/include/kofmod/lha.h \
           $(SDK)/include/kofmod/arj.h \
           $(SDK)/include/kofmod/lnk.h \
           $(SDK)/include/kofmod/reg.h \
           $(SDK)/include/kofmod/rtf.h \
           $(SDK)/include/kofmod/pdf.h \
           $(SDK)/include/kofmod/amsi.h \
           $(SDK)/include/kofmod/proc.h \
           $(SDK)/include/kofmod/clr.h \
           $(SDK)/include/kofmod/script.h \
           $(SDK)/include/kofshared/msf_pe.h \
           $(SDK)/include/kofshared/msf_elf64.h \
           $(SDK)/include/kofshared/msf_elf32.h \
           $(SDK)/include/kofmod/pe_reassemble.h \
           $(SDK)/include/kofmod/emu_harvest.h \
           $(SDK)/include/kofmod/ep_shape.h \
           $(SDK)/include/kofmod/stub_pat.h \
           $(SDK)/include/kofmod/upx_method.h \
           $(SDK)/include/celllysis/arch.h \
           $(SDK)/include/celllysis/cell.h \
           $(SDK)/include/celllysis/capability.h \
           $(SDK)/include/celllysis/capability_word.h \
           $(SDK)/include/celllysis/capability_ids.h \
           $(SDK)/include/celllysis/capability_flags.h \
           $(SDK)/include/celllysis/mutation_window.h \
           $(SDK)/include/genotype/image/elf_types.h \
           $(SDK)/include/genotype/image/pe_types.h \
           $(SDK)/include/genotype/image/clr_types.h \
           $(SDK)/include/genotype/image/section_flags.h \
           $(SDK)/include/range.h \
           $(SDK)/include/celllysis/xref.h \
           $(SDK)/include/phenotype/diag_vocab.h \
           $(SDK)/include/decompressors/aspack_tab.h \
           $(SDK)/include/decompressors/format_limits.h

$(SDK)/include/kofeng.h: libkofeng/kofeng.h
	@$(call MKDIR,$(dir $@))
	@$(call COPY,$<,$@)

$(SDK)/include/koftypes.h: libkofeng/kofcore/koftypes.h
	@$(call MKDIR,$(dir $@))
	@$(call COPY,$<,$@)

# koftypes.h and kofplatform.h are umbrellas over parts that sit beside them; a host
# includes the umbrella and the parts must be where it looks.
$(SDK)/include/kofobjname.h $(SDK)/include/kofresult.h $(SDK)/include/kofoption.h \
$(SDK)/include/kofplatform_os.h $(SDK)/include/kofplatform_file.h: \
$(SDK)/include/%.h: libkofeng/kofcore/%.h
	@$(call MKDIR,$(dir $@))
	@$(call COPY,$<,$@)

# The three core headers a host program (kofscanner) includes beside kofeng.h:
# buffers and the hash, the file and path calls that differ per platform, and the
# diagnostics switch. They name no engine type.
$(SDK)/include/kofcore.h: libkofeng/kofcore/kofcore.h
	@$(call MKDIR,$(dir $@))
	@$(call COPY,$<,$@)

$(SDK)/include/kofplatform.h: libkofeng/kofcore/kofplatform.h
	@$(call MKDIR,$(dir $@))
	@$(call COPY,$<,$@)

$(SDK)/include/kofdebug.h: libkofeng/kofcore/kofdebug.h
	@$(call MKDIR,$(dir $@))
	@$(call COPY,$<,$@)

$(SDK)/include/kofentropy.h: libkofeng/kofcore/kofentropy.h
	@$(call MKDIR,$(dir $@))
	@$(call COPY,$<,$@)

$(SDK)/include/kofhash.h: libkofeng/kofcore/kofhash.h
	@$(call MKDIR,$(dir $@))
	@$(call COPY,$<,$@)

# struct kof_range: core's own type, which <kofmod/kofsig.h> re-exports.
$(SDK)/include/range.h: libkofeng/kofcore/range.h
	@$(call MKDIR,$(dir $@))
	@$(call COPY,$<,$@)

# What kofeng.h includes from the verdictor, at the path it names it by.
$(SDK)/include/verdictor/verdict.h: libkofeng/verdictor/verdict.h
	@$(call MKDIR,$(dir $@))
	@$(call COPY,$<,$@)

# The malware family catalog the viewer's Manage > Malware Families dialog edits (kofexamine/kv_families.c).
$(SDK)/include/verdictor/famcat.h: libkofeng/verdictor/famcat.h
	@$(call MKDIR,$(dir $@))
	@$(call COPY,$<,$@)

$(SDK)/include/kofmod/%.h: libkofeng/kofcore/kofmod/%.h
	@$(call MKDIR,$(dir $@))
	@$(call COPY,$<,$@)

#
# WHAT A MODULE MAY INCLUDE, IN TWO NAMESPACES RATHER THAN ONE.
#
# kofmod/ is the ABI - the vtable, the enums, the macros a module is written
# against. It is not a dumping ground for anything a module happens to include,
# and it was becoming one.
#
# kofshared/ is what the modules of bases/ share among themselves: where a
# metasploit stub keeps its payload, what a shellcode entry looks like. It is
# the database's own knowledge, written per family, and the sources live in
# libkofeng/analyzers/diseases/ with the other analysis of one kind of
# malware - not in bases/, which holds only case routines.
#
# The helpers that put an object back together (pe_reassemble.h, emu_harvest.h,
# ep_shape.h) are module-side code over the ABI, so they sit in kofmod/ with it.
#
$(SDK)/include/kofshared/%.h: libkofeng/analyzers/diseases/%.h
	@$(call MKDIR,$(dir $@))
	@$(call COPY,$<,$@)

#
# THE TYPES THE ABI RE-EXPORTS, shipped under the layout the re-export names.
#
# kgenome defines what it analyses (the instruction form, the structure of an
# ELF/PE/CLR object, the capability words, the mutation window) and kuncoat the
# tables and limits of its algorithms; <kofmod/cell.h>, <kofmod/elf.h> and the
# others are thin files that include them as <celllysis/..>, <image/..> and
# <decompressors/..>. A module is built against this directory alone, so the same
# relative paths exist here as under -Ilibgenome and -Ilibuncoat.
#
$(SDK)/include/celllysis/%.h: libgenome/celllysis/%.h
	@$(call MKDIR,$(dir $@))
	@$(call COPY,$<,$@)

$(SDK)/include/genotype/image/%.h: libgenome/genotype/image/%.h
	@$(call MKDIR,$(dir $@))
	@$(call COPY,$<,$@)

$(SDK)/include/phenotype/%.h: libgenome/phenotype/%.h
	@$(call MKDIR,$(dir $@))
	@$(call COPY,$<,$@)

$(SDK)/include/decompressors/%.h: libuncoat/decompressors/%.h
	@$(call MKDIR,$(dir $@))
	@$(call COPY,$<,$@)

sdk: $(LIB) $(SDK_HDR)
	$(info $(SP)  $(LIB))

