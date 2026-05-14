int * __fastcall FUN_10026ac0(int *param_1)

{
  void *pvVar1;
  code *pcVar2;
  void *pvVar3;
  int *piVar4;
  
  if ((char)param_1[6] != '\0') {
    if (7 < (uint)param_1[5]) {
      pvVar1 = (void *)*param_1;
      pvVar3 = pvVar1;
      if ((0xfff < param_1[5] * 2 + 2U) &&
         (pvVar3 = *(void **)((int)pvVar1 + -4), 0x1f < (uint)((int)pvVar1 + (-4 - (int)pvVar3)))) {
        FUN_10032f7f();
        pcVar2 = (code *)swi(3);
        piVar4 = (int *)(*pcVar2)();
        return piVar4;
      }
      FUN_1002e346(pvVar3);
    }
    param_1[4] = 0;
    param_1[5] = 7;
    *(undefined2 *)param_1 = 0;
    *(undefined1 *)(param_1 + 6) = 0;
  }
  return param_1;
}


// FUNCTION_END

// FUNCTION_START: FUN_10026b30 @ 10026b30