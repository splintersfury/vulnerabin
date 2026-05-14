undefined * Catch_100287b5(void)

{
  int *piVar1;
  int *piVar2;
  int iVar3;
  int *this;
  char *pcVar4;
  int unaff_EBP;
  
  piVar1 = *(int **)(unaff_EBP + -0x34);
  piVar2 = *(int **)(unaff_EBP + -0x28);
  iVar3 = piVar1[3];
  piVar2[1] = piVar1[4];
  *piVar2 = iVar3;
  this = FUN_100034b0((int *)(unaff_EBP + -0xdc),4,0x1006118c);
  *(undefined1 *)(unaff_EBP + -4) = 3;
  if ((char)this[0x12] != '\0') {
    FUN_100082c0(this,L"get_hash_string err=");
    if ((char)this[0x12] != '\0') {
      FUN_10006730(this,*piVar2);
      if ((char)this[0x12] != '\0') {
        FUN_100082c0(this,(short *)&DAT_1006115c);
      }
    }
  }
  pcVar4 = (char *)(**(code **)(*piVar1 + 4))();
  if ((char)this[0x12] != '\0') {
    FUN_10007f80(this,pcVar4);
  }
  FUN_10003450(unaff_EBP + -0xdc);
  return &DAT_1002888d;
}


// FUNCTION_END

// FUNCTION_START: Catch@1002883e @ 1002883e