REPORT zfi_payment_run.

DATA: lt_data  TYPE TABLE OF bsis, " RISK: S/4HANA Legacy Table Dependency (R004)
      ls_data  TYPE bsis,
      lv_kunnr TYPE string.

START-OF-SELECTION.

  " RISK: SELECT * (R002) and misses ORDER BY at a HANA-database (R007)
  SELECT * FROM bsis INTO TABLE lt_data WHERE bukrs = '1000'.

  LOOP AT lt_data INTO ls_data.
    " RISK: SELECT inuti en LOOP - very severe prestanda problem (R001)
    SELECT SINGLE * FROM kna1 INTO @DATA(ls_cust) WHERE kunnr = lv_kunnr.
  ENDLOOP.
