undefined * Catch_10029ff6(void)

{
  int iVar1;
  int *piVar2;
  char *pcVar3;
  int unaff_EBP;
  
  piVar2 = FUN_100034b0((int *)(unaff_EBP + -0x55c),4,0x10061490);
  *(undefined1 *)(unaff_EBP + -4) = 0x20;
  if ((char)piVar2[0x12] != '\0') {
    FUN_100082c0(piVar2,L"err=");
  }
  iVar1 = *(int *)(unaff_EBP + -0x4a0);
  if ((char)piVar2[0x12] != '\0') {
    pcVar3 = (char *)(**(code **)(**(int **)(iVar1 + 0x10) + 4))();
    piVar2 = FUN_10007f80(piVar2,pcVar3);
    piVar2 = FUN_1002b8f0(piVar2);
    FUN_10006730(piVar2,*(undefined4 *)(iVar1 + 0xc));
  }
  FUN_10003450(unaff_EBP + -0x55c);
  return &DAT_1002a065;
}


// FUNCTION_END

// FUNCTION_START: FUN_1002a06d @ 1002a06d