# ------------------------------------------------------ kofexamine API tests (phase B of the examiner suite)
#
# tests/unit/kx_*.c: the terminal-free API of kofexamine/ (kofinspect*, kofscfind, goto_parse.h, codec_ui, the pure parts
# of the viewer). Linked like codec_forms: the units under test compiled beside the engine archive. Included from
# mk/tests.mk next to tests_orbit.mk and extended into UNIT_EXTRA after it is set.
KX_TESTS := kx_inspect kx_dump kx_viewpure kx_find kx_spl kx_dash kx_dashdata kx_dashapi kx_famdata

$(foreach t,$(KX_TESTS),$(eval UT_SRC_$(t) := $$(KOFINSPECT_SRC) $$(KOFEVT_SRC)))
$(foreach t,$(KX_TESTS),$(eval UT_INC_$(t) := -I$$(SDK)/include -Ilibkoforbit/evt))
$(foreach t,$(KX_TESTS),$(eval UT_LIB_$(t) := yes))
$(foreach t,$(KX_TESTS),$(eval UT_DEP_$(t) := $$(SDK_HDR)))

# The viewer's pure helpers live in kofview.c, which links alone (the same as out_clip).
UT_SRC_kx_viewpure := kofexamine/kofview.c
UT_INC_kx_viewpure := -I$(SDK)/include

# kv_find.c is #included by its test (static helpers); only the engine archive and the event library are linked.
UT_SRC_kx_find := $(KOFEVT_SRC)
UT_INC_kx_find := -I$(SDK)/include -Ilibkoforbit/evt -Ilibkoforbit/antarc -Ilibkoforbit/walk -Ilibkoforbit/proc -Ilibkoforbit/mon -Ilibkofeng $(EMU_INC)
UT_LIB_kx_find := yes
UT_DEP_kx_find := $(SDK_HDR) kofexamine/kv_find.c $(wildcard kofexamine/kv_*.h)

# kx_spl reads source files and links nothing of the examiner.
UT_SRC_kx_spl :=
UT_INC_kx_spl :=
UT_LIB_kx_spl :=
UT_DEP_kx_spl :=

# kx_dash #includes kv_props_table.c and kv_props_tab.c (the widget and the pages' static helpers) and stubs what the rest of the
# viewer answers; the scrollbar and the output helpers it draws with are kofview.c's.
UT_SRC_kx_dash := $(KOFINSPECT_SRC) $(KOFEVT_SRC) kofexamine/kofview.c kofexamine/kofscfind.c
UT_INC_kx_dash := -I$(SDK)/include -Ilibkoforbit/evt -Ilibkoforbit/antarc -Ilibkoforbit/walk -Ilibkoforbit/proc -Ilibkoforbit/mon -Ilibkofeng $(EMU_INC)
UT_LIB_kx_dash := yes
UT_LDX_kx_dash := -Wl,--wrap=kgenome_infect_regions -Wl,--wrap=kofscfind_list
UT_DEP_kx_dash := $(SDK_HDR) kofexamine/kv_table.c kofexamine/kv_dash_dialog.c kofexamine/kv_props_table.c kofexamine/kv_props_tab.c kofexamine/kv_dashdata.c tests/unit/kx_dash_stubs.h $(wildcard kofexamine/kv_*.h)

# kx_dashdata #includes kv_dashdata.c alone: the dashboard's content as data, asserted on with no widget and no screen.
UT_SRC_kx_dashdata := $(KOFINSPECT_SRC) $(KOFEVT_SRC) kofexamine/kofview.c kofexamine/kofscfind.c
UT_INC_kx_dashdata := $(UT_INC_kx_dash)
UT_LIB_kx_dashdata := yes
UT_DEP_kx_dashdata := $(SDK_HDR) kofexamine/kv_dashdata.c tests/unit/kx_dash_stubs.h $(wildcard kofexamine/kv_*.h)

# kx_dashapi #includes kv_table.c and kv_dash_dialog.c: the table renderer and the dialog frame as pure functions (the scrollbar cell is kofview.c's).
UT_SRC_kx_dashapi := kofexamine/kofview.c
UT_INC_kx_dashapi := $(UT_INC_kx_dash)
UT_LIB_kx_dashapi := yes
UT_DEP_kx_dashapi := $(SDK_HDR) kofexamine/kv_table.c kofexamine/kv_dash_dialog.c $(wildcard kofexamine/kv_*.h)

# kx_famdata #includes kv_famdata.c and kv_table.c: the Malware Families dialog's rows, cells, button spans and tick menu as data.
UT_DEP_kx_famdata := $(SDK_HDR) kofexamine/kv_famdata.c kofexamine/kv_famdata.h kofexamine/kv_table.c $(wildcard kofexamine/kv_*.h)
