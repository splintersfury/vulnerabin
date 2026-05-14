void __thiscall FUN_1001b840(void *this,int param_1,int param_2,int param_3)

{
  code *pcVar1;
  char *pcVar2;
  char *pcVar3;
  
                    /* WARNING: Load size is inaccurate */
  pcVar2 = *this;
  if (pcVar2 != (char *)0x0) {
    pcVar3 = *(char **)((int)this + 4);
    if (pcVar2 != pcVar3) {
      do {
        FUN_1000e760(pcVar2);
        pcVar2 = pcVar2 + 0x10;
      } while (pcVar2 != pcVar3);
                    /* WARNING: Load size is inaccurate */
      pcVar2 = *this;
    }
    pcVar3 = pcVar2;
    if ((0xfff < (*(int *)((int)this + 8) - (int)pcVar2 & 0xfffffff0U)) &&
       (pcVar3 = *(char **)(pcVar2 + -4), (char *)0x1f < pcVar2 + (-4 - (int)pcVar3))) {
      FUN_10032f7f();
      pcVar1 = (code *)swi(3);
      (*pcVar1)();
      return;
    }
    FUN_1002e346(pcVar3);
  }
  *(int *)this = param_1;
  *(int *)((int)this + 4) = param_2 * 0x10 + param_1;
  *(int *)((int)this + 8) = param_3 * 0x10 + param_1;
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_1001b8c0 @ 1001b8c0