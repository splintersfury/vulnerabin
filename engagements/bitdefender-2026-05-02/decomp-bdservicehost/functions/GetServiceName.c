undefined8 * GetServiceName(void)

{
  undefined8 *puVar1;
  
                    /* 0x15250  1  GetServiceName */
  puVar1 = DAT_14007acf0;
  if (7 < (ulonglong)DAT_14007acf0[3]) {
    puVar1 = (undefined8 *)*DAT_14007acf0;
  }
  return puVar1;
}


// FUNCTION_END

// FUNCTION_START: FUN_140015270 @ 140015270