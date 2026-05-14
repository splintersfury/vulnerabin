void __fastcall FUN_1001ab00(undefined4 *param_1)

{
  int *piVar1;
  code *pcVar2;
  char *pcVar3;
  char *pcVar4;
  
  piVar1 = (int *)*param_1;
  if (piVar1 == (int *)0x0) {
    return;
  }
  pcVar3 = (char *)*piVar1;
  if (pcVar3 != (char *)0x0) {
    pcVar4 = (char *)piVar1[1];
    if (pcVar3 != pcVar4) {
      do {
        FUN_1000e760(pcVar3);
        pcVar3 = pcVar3 + 0x10;
      } while (pcVar3 != pcVar4);
      pcVar3 = (char *)*piVar1;
    }
    pcVar4 = pcVar3;
    if ((0xfff < (piVar1[2] - (int)pcVar3 & 0xfffffff0U)) &&
       (pcVar4 = *(char **)(pcVar3 + -4), (char *)0x1f < pcVar3 + (-4 - (int)pcVar4))) {
      FUN_10032f7f();
      pcVar2 = (code *)swi(3);
      (*pcVar2)();
      return;
    }
    FUN_1002e346(pcVar4);
    *piVar1 = 0;
    piVar1[1] = 0;
    piVar1[2] = 0;
  }
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_1001ab10 @ 1001ab10