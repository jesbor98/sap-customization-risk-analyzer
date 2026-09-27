REPORT zfi_legacy_select.

DATA: lt_bsis TYPE TABLE OF bsis,
      ls_bsis TYPE bsis,
      lv_bukrs TYPE bukrs.

START-OF-SELECTION.

  lv_bukrs = '1000'.

  SELECT * FROM bsis INTO TABLE lt_bsis WHERE bukrs = lv_bukrs.

  LOOP AT lt_bsis INTO ls_bsis.
    SELECT SINGLE * FROM kna1 INTO @DATA(ls_kna1) WHERE kunnr = ls_bsis-kunnr.
  ENDLOOP.

  CALL FUNCTION 'WS_DOWNLOAD'
    EXPORTING
      filename = 'C:\temp\legacy_export.txt'.
