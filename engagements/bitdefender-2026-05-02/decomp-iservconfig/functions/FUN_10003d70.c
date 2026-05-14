void __fastcall FUN_10003d70(int param_1)

{
  void *pvVar1;
  code *pcVar2;
  void *pvVar3;
  
  if (7 < *(uint *)(param_1 + 0x30)) {
    pvVar1 = *(void **)(param_1 + 0x1c);
    pvVar3 = pvVar1;
    if ((0xfff < *(uint *)(param_1 + 0x30) * 2 + 2) &&
       (pvVar3 = *(void **)((int)pvVar1 + -4), 0x1f < (uint)((int)pvVar1 + (-4 - (int)pvVar3))))
    goto LAB_10003e09;
    FUN_1002e346(pvVar3);
  }
  *(undefined4 *)(param_1 + 0x2c) = 0;
  *(undefined4 *)(param_1 + 0x30) = 7;
  *(undefined2 *)(param_1 + 0x1c) = 0;
  if (7 < *(uint *)(param_1 + 0x18)) {
    pvVar1 = *(void **)(param_1 + 4);
    pvVar3 = pvVar1;
    if ((0xfff < *(uint *)(param_1 + 0x18) * 2 + 2) &&
       (pvVar3 = *(void **)((int)pvVar1 + -4), 0x1f < (uint)((int)pvVar1 + (-4 - (int)pvVar3)))) {
LAB_10003e09:
      FUN_10032f7f();
      pcVar2 = (code *)swi(3);
      (*pcVar2)();
      return;
    }
    FUN_1002e346(pvVar3);
  }
  *(undefined4 *)(param_1 + 0x14) = 0;
  *(undefined4 *)(param_1 + 0x18) = 7;
  *(undefined2 *)(param_1 + 4) = 0;
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_10003e10 @ 10003e10