/*
 * kv_evt_private.h - the event panel's units: what one of them offers another.
 *
 * The panel was one file (kv_evt.c) and is four, cut by job:
 *   kv_evt_rows.c  the record's rows - the palette, which colour a field owns, the three zones, the byte colour;
 *   kv_evt_box.c   the submission's text box and the selection in it, kept in step with the hex pane;
 *   kv_evt_load.c  taking a copy of the selected event and gathering the content behind it;
 *   kv_evt.c       the drawing.
 * What other units of the viewer call stays declared in kv_shared.h under the same names; this header holds
 * only what the four share. Not part of any surface: included after kv.h by those four files.
 */
#ifndef KV_EVT_PRIVATE_H
#define KV_EVT_PRIVATE_H

/* kv_evt_rows.c */
const char *evt_row_colour(const char *name);
const char *evt_row_ink(const char *name);
const char *evt_row_value(const struct view *v, int i, char *val, size_t cap);

/* kv_evt_box.c */
int evt_box_x(void);
int evt_box_w(void);
int evt_box_extent(const struct view *v, uint16_t *off, int *step);

#endif /* KV_EVT_PRIVATE_H */
