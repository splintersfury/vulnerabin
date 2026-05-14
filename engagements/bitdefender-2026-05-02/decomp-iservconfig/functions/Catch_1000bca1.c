undefined * Catch_1000bca1(void)

{
  uint *puVar1;
  undefined4 *puVar2;
  int unaff_EBP;
  
  puVar1 = (uint *)(**(code **)(**(int **)(unaff_EBP + -0x68) + 4))();
  puVar2 = FUN_10014620((undefined4 *)(unaff_EBP + -0x88),0xd,puVar1);
  puVar2 = FUN_100143d0((undefined4 *)(unaff_EBP + -0xb8),puVar2);
  FUN_10014420(*(void **)(unaff_EBP + -0x4c),puVar2);
  FUN_1000bd80(unaff_EBP + -0xb8);
  FUN_1000bd80(unaff_EBP + -0x88);
  return &DAT_1000bcf4;
}


// FUNCTION_END

// FUNCTION_START: FUN_1000bd02 @ 1000bd02