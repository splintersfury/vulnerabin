void __fastcall FUN_10018360(int *param_1)

{
  code *pcVar1;
  char *pcVar2;
  char *pcVar3;
  
  pcVar2 = (char *)*param_1;
  if (pcVar2 != (char *)0x0) {
    pcVar3 = (char *)param_1[1];
    if (pcVar2 != pcVar3) {
      do {
        FUN_1000e760(pcVar2);
        pcVar2 = pcVar2 + 0x10;
      } while (pcVar2 != pcVar3);
      pcVar2 = (char *)*param_1;
    }
    pcVar3 = pcVar2;
    if ((0xfff < (param_1[2] - (int)pcVar2 & 0xfffffff0U)) &&
       (pcVar3 = *(char **)(pcVar2 + -4), (char *)0x1f < pcVar2 + (-4 - (int)pcVar3))) {
      FUN_10032f7f();
      pcVar1 = (code *)swi(3);
      (*pcVar1)();
      return;
    }
    FUN_1002e346(pcVar3);
    *param_1 = 0;
    param_1[1] = 0;
    param_1[2] = 0;
  }
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_100183d0 @ 100183d0