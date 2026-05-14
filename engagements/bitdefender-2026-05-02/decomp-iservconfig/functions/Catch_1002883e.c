undefined * Catch_1002883e(void)

{
  undefined4 *puVar1;
  int *piVar2;
  int unaff_EBP;
  
  puVar1 = *(undefined4 **)(unaff_EBP + -0x28);
  *puVar1 = 8;
  puVar1[1] = &PTR_vftable_10069ab8;
  piVar2 = FUN_100034b0((int *)(unaff_EBP + -0x184),4,0x1006118c);
  *(undefined1 *)(unaff_EBP + -4) = 4;
  if ((char)piVar2[0x12] != '\0') {
    FUN_100082c0(piVar2,L"failed with std::bad_alloc");
  }
  FUN_10003450(unaff_EBP + -0x184);
  return &DAT_1002888d;
}


// FUNCTION_END

// FUNCTION_START: FUN_100288a9 @ 100288a9