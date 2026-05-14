void __fastcall FUN_1000d1f0(int param_1)

{
  void *pvVar1;
  code *pcVar2;
  void *pvVar3;
  
  if (7 < *(uint *)(param_1 + 0x18)) {
    pvVar1 = *(void **)(param_1 + 4);
    pvVar3 = pvVar1;
    if ((0xfff < *(uint *)(param_1 + 0x18) * 2 + 2) &&
       (pvVar3 = *(void **)((int)pvVar1 + -4), 0x1f < (uint)((int)pvVar1 + (-4 - (int)pvVar3)))) {
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

// FUNCTION_START: FUN_1000d250 @ 1000d250