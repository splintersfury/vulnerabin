void __fastcall FUN_1000bd80(int param_1)

{
  void *pvVar1;
  code *pcVar2;
  void *pvVar3;
  
  if (0xf < *(uint *)(param_1 + 0x1c)) {
    pvVar1 = *(void **)(param_1 + 8);
    pvVar3 = pvVar1;
    if ((0xfff < *(uint *)(param_1 + 0x1c) + 1) &&
       (pvVar3 = *(void **)((int)pvVar1 + -4), 0x1f < (uint)((int)pvVar1 + (-4 - (int)pvVar3)))) {
      FUN_10032f7f();
      pcVar2 = (code *)swi(3);
      (*pcVar2)();
      return;
    }
    FUN_1002e346(pvVar3);
  }
  *(undefined4 *)(param_1 + 0x18) = 0;
  *(undefined4 *)(param_1 + 0x1c) = 0xf;
  *(undefined1 *)(param_1 + 8) = 0;
  return;
}


// FUNCTION_END

// FUNCTION_START: thunk_FUN_1000e2c0 @ 1000bdd0