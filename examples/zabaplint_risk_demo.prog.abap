REPORT zabaplint_risk_demo.

DATA lt_data TYPE TABLE OF mara.
DATA ls_data TYPE mara.

START-OF-SELECTION.

  LOOP AT lt_data INTO ls_data.
    SELECT SINGLE * FROM kna1 INTO ls_data.
  ENDLOOP.

  SELECT * FROM bsis INTO TABLE lt_data.

  CALL TRANSACTION 'FB01'.

  MOVE '1000' TO ls_data-matnr.

  UPDATE mara SET matkl = '001' WHERE matnr = '000000000000000001'.

  DATA(lv_broken) = .
