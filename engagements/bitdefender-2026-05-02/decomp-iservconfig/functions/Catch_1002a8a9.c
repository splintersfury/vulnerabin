undefined * Catch_1002a8a9(void)

{
  int iVar1;
  int *piVar2;
  char *pcVar3;
  int unaff_EBP;
  
  piVar2 = FUN_100034b0((int *)(unaff_EBP + -0x588),4,0x100614cc);
  *(undefined1 *)(unaff_EBP + -4) = 0x27;
  if ((char)piVar2[0x12] != '\0') {
    FUN_100082c0(piVar2,L"err=");
  }
  iVar1 = *(int *)(unaff_EBP + -0x4c8);
  if ((char)piVar2[0x12] != '\0') {
    pcVar3 = (char *)(**(code **)(**(int **)(iVar1 + 0x10) + 4))();
    piVar2 = FUN_10007f80(piVar2,pcVar3);
    piVar2 = FUN_1002b8f0(piVar2);
    FUN_10006730(piVar2,*(undefined4 *)(iVar1 + 0xc));
  }
  FUN_10003450(unaff_EBP + -0x588);
  return &DAT_1002a91d;
}


// FUNCTION_END

// FUNCTION_START: FUN_1002a926 @ 1002a926