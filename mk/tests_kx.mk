# ------------------------------------------------------ kofexamine API tests (phase B of the examiner suite)
#
# tests/unit/kx_*.c: the terminal-free API of kofexamine/ (kofinspect*, kofscfind, goto_parse.h, codec_ui, the pure parts
# of the viewer). Linked like codec_forms: the units under test compiled beside the engine archive. Included from
# mk/tests.mk next to tests_orbit.mk and extended into UNIT_EXTRA after it is set.
KX_TESTS := kx_inspect kx_dump kx_viewpure kx_find kx_spl kx_dash kx_dashdata kx_dashapi kx_famdata kx_tagdata kx_formdata kx_popup kx_input kx_form kx_identify kx_clip kx_dlgsel kx_graph kx_graph_chain

$(foreach t,$(KX_TESTS),$(eval UT_SRC_$(t) := $$(KOFINSPECT_SRC) $$(KOFEVT_SRC)))
$(foreach t,$(KX_TESTS),$(eval UT_INC_$(t) := -I$$(SDK)/include -Ilibkoforbit/evt))
$(foreach t,$(KX_TESTS),$(eval UT_LIB_$(t) := yes))
$(foreach t,$(KX_TESTS),$(eval UT_DEP_$(t) := $$(SDK_HDR)))

# The viewer's pure helpers live in kofview.c, which links alone (the same as out_clip).
UT_SRC_kx_viewpure := $(KOFVIEW_SRC)
UT_INC_kx_viewpure := -I$(SDK)/include

# The pop-up list (kv_popup.h): its functions are kofview.c's, and a test of them needs nothing else.
UT_SRC_kx_popup := $(KOFVIEW_SRC)
UT_INC_kx_popup := -I$(SDK)/include
UT_DEP_kx_popup := $(SDK_HDR) kofexamine/kv_popup.h kofexamine/kofview.h

# kv_find.c is #included by its test (static helpers); only the engine archive and the event library are linked.
UT_SRC_kx_find := $(KOFEVT_SRC)
UT_INC_kx_find := -I$(SDK)/include -Ilibkoforbit/evt -Ilibkoforbit/antarc -Ilibkoforbit/walk -Ilibkoforbit/proc -Ilibkoforbit/mon -Ilibkofeng $(EMU_INC)
UT_LIB_kx_find := yes
UT_DEP_kx_find := $(SDK_HDR) kofexamine/kv_find.c $(wildcard kofexamine/kv_*.h kofexamine/kv_*.inc)

# kv_input.c is #included by its test (static mouse readers, stdin is a pipe the test fills).
UT_SRC_kx_input := $(KOFEVT_SRC)
UT_INC_kx_input := $(UT_INC_kx_find)
UT_LIB_kx_input := yes
UT_DEP_kx_input := $(SDK_HDR) kofexamine/kv_input.c $(wildcard kofexamine/kv_*.h kofexamine/kv_*.inc)
UT_LDX_kx_input := -no-pie -Wl,--unresolved-symbols=ignore-all

# kv_form.c is #included by its test (the tick-cell writer); kofview.c is linked for the output buffer.
UT_SRC_kx_form := $(KOFEVT_SRC) $(KOFVIEW_SRC) kofexamine/kv_formdata.c
UT_INC_kx_form := $(UT_INC_kx_find)
UT_LIB_kx_form := yes
# the rest of the viewer is not linked: its data and functions are left unresolved (never reached by the tick-cell writer)
UT_LDX_kx_form := -no-pie -Wl,--unresolved-symbols=ignore-all
UT_DEP_kx_form := $(SDK_HDR) kofexamine/kv_form.c $(wildcard kofexamine/kv_*.h kofexamine/kv_*.inc)

# kv_clip.c is #included by its test (the clipboard helpers); the rest of the viewer is left unresolved, never reached.
UT_SRC_kx_clip := $(KOFEVT_SRC) $(KOFVIEW_SRC)
UT_INC_kx_clip := $(UT_INC_kx_find)
UT_LDX_kx_clip := -no-pie -Wl,--unresolved-symbols=ignore-all
UT_DEP_kx_clip := $(SDK_HDR) kofexamine/kv_clip.c $(wildcard kofexamine/kv_*.h kofexamine/kv_*.inc)

# kv_dlgsel.c is #included by its test (the selection text); the rest of the viewer is not linked.
UT_SRC_kx_dlgsel := $(KOFEVT_SRC) $(KOFVIEW_SRC)
UT_INC_kx_dlgsel := $(UT_INC_kx_find)
UT_LDX_kx_dlgsel := -no-pie -Wl,--unresolved-symbols=ignore-all
UT_DEP_kx_dlgsel := $(SDK_HDR) kofexamine/kv_dlgsel.c $(wildcard kofexamine/kv_*.h kofexamine/kv_*.inc)

# kx_identify wraps kof_parser_list to hand kof_inspect_identify a table of its own.
UT_LDX_kx_identify := -Wl,--wrap=kof_parser_list

# kx_spl reads source files and links nothing of the examiner.
UT_SRC_kx_spl :=
UT_INC_kx_spl :=
UT_LIB_kx_spl :=
UT_DEP_kx_spl :=

# kx_dash #includes kv_props_table.c and kv_props_tab.c (the widget and the pages' static helpers) and stubs what the rest of the
# viewer answers; the scrollbar and the output helpers it draws with are kofview.c's.
UT_SRC_kx_dash := $(KOFINSPECT_SRC) $(KOFEVT_SRC) $(KOFVIEW_SRC) kofexamine/kofscfind.c
UT_INC_kx_dash := -I$(SDK)/include -Ilibkoforbit/evt -Ilibkoforbit/antarc -Ilibkoforbit/walk -Ilibkoforbit/proc -Ilibkoforbit/mon -Ilibkofeng $(EMU_INC)
UT_LIB_kx_dash := yes
UT_LDX_kx_dash := -Wl,--wrap=kgenome_infect_regions -Wl,--wrap=kofscfind_list
UT_DEP_kx_dash := $(SDK_HDR) kofexamine/kv_table.c kofexamine/kv_dash_dialog.c kofexamine/kv_props_table.c kofexamine/kv_props_tab.c kofexamine/kv_dashdata.c tests/unit/kx_dash_stubs.h $(wildcard kofexamine/kv_*.h kofexamine/kv_*.inc)

# kx_dashdata #includes kv_dashdata.c alone: the dashboard's content as data, asserted on with no widget and no screen.
UT_SRC_kx_dashdata := $(KOFINSPECT_SRC) $(KOFEVT_SRC) $(KOFVIEW_SRC) kofexamine/kofscfind.c
UT_INC_kx_dashdata := $(UT_INC_kx_dash)
UT_LIB_kx_dashdata := yes
UT_LDX_kx_dashdata := -Wl,--wrap=malloc
UT_DEP_kx_dashdata := $(SDK_HDR) kofexamine/kv_dashdata.c tests/unit/kx_dash_stubs.h $(wildcard kofexamine/kv_*.h kofexamine/kv_*.inc)

# kx_dashapi #includes kv_table.c and kv_dash_dialog.c: the table renderer and the dialog frame as pure functions (the scrollbar cell is kofview.c's).
UT_SRC_kx_dashapi := $(KOFVIEW_SRC)
UT_INC_kx_dashapi := $(UT_INC_kx_dash)
UT_LIB_kx_dashapi := yes
UT_DEP_kx_dashapi := $(SDK_HDR) kofexamine/kv_table.c kofexamine/kv_dash_dialog.c $(wildcard kofexamine/kv_*.h kofexamine/kv_*.inc)

# kx_famdata and kx_tagdata include kv_dash_dialog.c (the shared content size and buttons), whose scrollbar cell is kofview.c's.
UT_SRC_kx_famdata := $(KOFINSPECT_SRC) $(KOFEVT_SRC) $(KOFVIEW_SRC)
UT_SRC_kx_tagdata := $(KOFINSPECT_SRC) $(KOFEVT_SRC) $(KOFVIEW_SRC)

# kx_famdata #includes kv_famdata.c and kv_table.c: the Malware Families dialog's rows, cells, button spans and tick menu as data.
UT_DEP_kx_famdata := $(SDK_HDR) kofexamine/kv_famdata.c kofexamine/kv_famdata.h kofexamine/kv_ftext.c kofexamine/kv_table.c kofexamine/kv_dash_dialog.c $(wildcard kofexamine/kv_*.h kofexamine/kv_*.inc)

# kx_tagdata #includes kv_tagdata.c, kv_table.c and kv_dash_dialog.c: the Syndromes dialog's rows, cells, click extents, buttons and tick
# menu as data (the shared units are the ones Pathogens' kx_famdata uses).
UT_DEP_kx_tagdata := $(SDK_HDR) kofexamine/kv_tagdata.c kofexamine/kv_tagdata.h kofexamine/kv_table.c kofexamine/kv_dash_dialog.c $(wildcard kofexamine/kv_*.h kofexamine/kv_*.inc) kofexamine/kv_formdata.h

# kx_formdata #includes kv_formdata.c alone: the small form's measures (cell and grid width, the size) as pure functions.
UT_SRC_kx_formdata := $(KOFINSPECT_SRC) $(KOFEVT_SRC)
UT_DEP_kx_formdata := $(SDK_HDR) kofexamine/kv_formdata.c kofexamine/kv_formdata.h kofexamine/kv_pick.h

# kx_graph is the viewer's graph drawing (kv_graph.c) as a pure module: it #includes it (KV_GRAPH_SRC: tools/mutate_kv_graph.py names a mutant here) and links nothing of the examiner;
# the allocator is wrapped to refuse the Nth call. kx_graph_chain draws the engine's graph of a function assembled from bytes.
UT_SRC_kx_graph :=
UT_INC_kx_graph :=
UT_LIB_kx_graph :=
UT_LDX_kx_graph := -Wl,--wrap=malloc -Wl,--wrap=calloc -Wl,--wrap=free
UT_DEP_kx_graph := kofexamine/kv_graph.c kofexamine/kv_graph_rank.c kofexamine/kv_graph_route.c kofexamine/kv_graph_paint.c kofexamine/kv_graph_private.h kofexamine/kv_graph.h kofexamine/kofview.h tests/unit/kx_graph_gold.h

UT_SRC_kx_graph_chain :=
UT_INC_kx_graph_chain := -Ilibgenome -Ilibkofeng -Ilibkofeng/kofcore -Ilibkofeng/analyzers -I$(SDK)/include
UT_LIB_kx_graph_chain := yes
UT_DEP_kx_graph_chain := $(SDK_HDR) kofexamine/kv_graph.c kofexamine/kv_graph_rank.c kofexamine/kv_graph_route.c kofexamine/kv_graph_paint.c kofexamine/kv_graph_private.h kofexamine/kv_graph.h tests/unit/kx_graph_chain_gold.h
