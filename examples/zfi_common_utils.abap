*----------------------------------------------------------------------*
* INCLUDE ZFI_COMMON_UTILS
*----------------------------------------------------------------------*

" RISK: Hard coded value (R003)
IF sy-sysid = 'DEV' AND ls_data-bukrs = '0001'.
  "RISK: REFRESH is obsolete (R008)
  REFRESH lt_data.
ENDIF.
