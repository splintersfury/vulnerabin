undefined * Catch_10029077(void)

{
  int *piVar1;
  int *piVar2;
  char *pcVar3;
  int *piVar4;
  int unaff_EBP;
  
  piVar2 = FUN_100034b0((int *)(unaff_EBP + -0x520),4,0x10061380);
  *(undefined1 *)(unaff_EBP + -4) = 0x13;
  if ((char)piVar2[0x12] != '\0') {
    FUN_100082c0(piVar2,L"err=");
  }
  piVar1 = *(int **)(unaff_EBP + -0x464);
  if ((char)piVar2[0x12] != '\0') {
    pcVar3 = (char *)(**(code **)(*(int *)piVar1[4] + 4))();
    piVar4 = FUN_10007f80(piVar2,pcVar3);
    piVar4 = FUN_1002b8f0(piVar4);
    FUN_10006730(piVar4,piVar1[3]);
    if ((char)piVar2[0x12] != '\0') {
      FUN_100082c0(piVar2,(short *)&DAT_1006115c);
    }
  }
  pcVar3 = (char *)(**(code **)(*piVar1 + 4))();
  if ((char)piVar2[0x12] != '\0') {
    FUN_10007f80(piVar2,pcVar3);
  }
  FUN_10003450(unaff_EBP + -0x520);
  return &DAT_1002910e;
}


// FUNCTION_END

// FUNCTION_START: FUN_1002913a @ 1002913a