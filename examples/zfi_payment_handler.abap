CLASS zcl_payment_handler DEFINITION PUBLIC FINAL CREATE PUBLIC.
  PUBLIC SECTION.
    METHODS: process_bulk_payments.
ENDCLASS.

CLASS zcl_payment_handler IMPLEMENTATION.
  METHOD process_bulk_payments.
    DATA: lt_vendors TYPE TABLE OF bsi_fake, " Simulated field
          ls_vendor  TYPE string.

    " RISK: Misses authority check before critical modifier(R010)
    " RISK: Direct database modifier at a standard table (R006)
    UPDATE zpay_status SET status = 'EXECUTED' WHERE mandt = '100'.

    " RISK: MOVE is obosolete element according to abaplint (R008)
    MOVE '1000' TO ls_vendor.

  ENDMETHOD.
ENDCLASS.
