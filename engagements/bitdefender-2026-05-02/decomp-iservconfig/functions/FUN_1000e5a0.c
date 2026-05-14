void __fastcall FUN_1000e5a0(char *param_1)

{
  void *pvVar1;
  code *pcVar2;
  void *pvVar3;
  
  if (param_1[0x20] != -1) {
    if (param_1[0x20] == '\0') {
      FUN_1000e760(param_1);
      return;
    }
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
    param_1[0x18] = '\0';
    param_1[0x19] = '\0';
    param_1[0x1a] = '\0';
    param_1[0x1b] = '\0';
    param_1[0x1c] = '\x0f';
    param_1[0x1d] = '\0';
    param_1[0x1e] = '\0';
    param_1[0x1f] = '\0';
    param_1[8] = '\0';
  }
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_1000e610 @ 1000e610