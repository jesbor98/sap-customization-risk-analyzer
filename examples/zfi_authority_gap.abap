REPORT zfi_authority_gap.

DATA: lt_bseg TYPE TABLE OF bseg,
      lv_bukrs TYPE bukrs.

START-OF-SELECTION.

  lv_bukrs = '1000'.

  SELECT * FROM bseg INTO TABLE lt_bseg WHERE bukrs = lv_bukrs.

  CALL TRANSACTION 'FB01'.
