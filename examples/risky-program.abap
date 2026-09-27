REPORT z_s4_migration_test.

DATA: lt_bsis TYPE TABLE OF bsis.

START-OF-SELECTION.

  SELECT * FROM bsis INTO TABLE lt_bsis WHERE bukrs = '1000'.

  CALL FUNCTION 'WS_DOWNLOAD'
    EXPORTING
      filename = 'C:\temp\export.txt'.

  UPDATE zcustomer SET status = 'A' WHERE kunnr = '0000012345'.
