void __fastcall FUN_10023be0(int param_1)

{
  int iVar1;
  void *pvVar2;
  code *pcVar3;
  void *pvVar4;
  
  iVar1 = *(int *)(param_1 + 4);
  if (iVar1 != 0) {
    if (7 < *(uint *)(iVar1 + 0x28)) {
      pvVar2 = *(void **)(iVar1 + 0x14);
      pvVar4 = pvVar2;
      if ((0xfff < *(uint *)(iVar1 + 0x28) * 2 + 2) &&
         (pvVar4 = *(void **)((int)pvVar2 + -4), 0x1f < (uint)((int)pvVar2 + (-4 - (int)pvVar4)))) {
        FUN_10032f7f();
        pcVar3 = (code *)swi(3);
        (*pcVar3)();
        return;
      }
      FUN_1002e346(pvVar4);
    }
    *(undefined4 *)(iVar1 + 0x24) = 0;
    *(undefined4 *)(iVar1 + 0x28) = 7;
    *(undefined2 *)(iVar1 + 0x14) = 0;
  }
  if (*(void **)(param_1 + 4) != (void *)0x0) {
    FUN_1002e346(*(void **)(param_1 + 4));
  }
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_10023c50 @ 10023c50