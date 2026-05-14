void __fastcall FUN_1002b200(int *param_1)

{
  void *pvVar1;
  code *pcVar2;
  void *pvVar3;
  
  if ((int *)*param_1 != (int *)0x0) {
    FUN_1002b510((int *)*param_1,(int *)param_1[1]);
    pvVar1 = (void *)*param_1;
    pvVar3 = pvVar1;
    if ((0xfff < (uint)(((param_1[2] - (int)pvVar1) / 0x18) * 0x18)) &&
       (pvVar3 = *(void **)((int)pvVar1 + -4), 0x1f < (uint)((int)pvVar1 + (-4 - (int)pvVar3)))) {
      FUN_10032f7f();
      pcVar2 = (code *)swi(3);
      (*pcVar2)();
      return;
    }
    FUN_1002e346(pvVar3);
    *param_1 = 0;
    param_1[1] = 0;
    param_1[2] = 0;
  }
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_1002b280 @ 1002b280