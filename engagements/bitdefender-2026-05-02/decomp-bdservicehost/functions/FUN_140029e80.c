void FUN_140029e80(longlong *param_1,longlong param_2,longlong param_3,longlong param_4)

{
  char *pcVar1;
  code *pcVar2;
  char *pcVar3;
  
  pcVar3 = (char *)*param_1;
  if (pcVar3 != (char *)0x0) {
    pcVar1 = (char *)param_1[1];
    if (pcVar3 != pcVar1) {
      do {
        FUN_14001cf70(pcVar3);
        pcVar3 = pcVar3 + 0x10;
      } while (pcVar3 != pcVar1);
      pcVar3 = (char *)*param_1;
    }
    if ((0xfff < (param_1[2] - (longlong)pcVar3 & 0xfffffffffffffff0U)) &&
       ((char *)0x1f < pcVar3 + (-8 - *(longlong *)(pcVar3 + -8)))) {
      FUN_140035d28();
      pcVar2 = (code *)swi(3);
      (*pcVar2)();
      return;
    }
    FUN_14002f180();
  }
  *param_1 = param_2;
  param_1[1] = param_3 * 0x10 + param_2;
  param_1[2] = param_4 * 0x10 + param_2;
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_140029f50 @ 140029f50