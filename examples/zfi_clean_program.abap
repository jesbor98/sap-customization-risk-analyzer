REPORT zfi_clean_program.

DATA: lt_vbak TYPE TABLE OF vbak,
      lv_vbeln TYPE vbeln.

START-OF-SELECTION.

  SELECT vbeln audat FROM vbak INTO TABLE lt_vbak WHERE erdat = sy-datum.

  SORT lt_vbak BY vbeln.

  LOOP AT lt_vbak INTO lv_vbeln.
    WRITE: / lv_vbeln.
  ENDLOOP.
