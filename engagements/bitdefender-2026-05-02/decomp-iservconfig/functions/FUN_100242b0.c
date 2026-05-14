void __fastcall FUN_100242b0(undefined4 *param_1)

{
  int *piVar1;
  void *pvVar2;
  code *pcVar3;
  void *pvVar4;
  
  piVar1 = (int *)*param_1;
  if (piVar1 != (int *)0x0) {
    if (7 < (uint)piVar1[5]) {
      pvVar2 = (void *)*piVar1;
      pvVar4 = pvVar2;
      if ((0xfff < piVar1[5] * 2 + 2U) &&
         (pvVar4 = *(void **)((int)pvVar2 + -4), 0x1f < (uint)((int)pvVar2 + (-4 - (int)pvVar4)))) {
        FUN_10032f7f();
        pcVar3 = (code *)swi(3);
        (*pcVar3)();
        return;
      }
      FUN_1002e346(pvVar4);
    }
    piVar1[4] = 0;
    piVar1[5] = 7;
    *(undefined2 *)piVar1 = 0;
  }
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_10024310 @ 10024310