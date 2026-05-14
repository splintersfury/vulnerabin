undefined * Catch_All_1000c1a9(void)

{
  undefined4 *puVar1;
  int unaff_EBP;
  
  puVar1 = *(undefined4 **)(unaff_EBP + -0x40);
  *puVar1 = 8;
  puVar1[1] = &PTR_vftable_10069ab8;
  puVar1 = *(undefined4 **)(unaff_EBP + -0x3c);
  *puVar1 = 0;
  puVar1[4] = 0;
  puVar1[5] = 7;
  *(undefined2 *)puVar1 = 0;
  return &DAT_1000c1de;
}


// FUNCTION_END

// FUNCTION_START: FUN_1000c1ec @ 1000c1ec