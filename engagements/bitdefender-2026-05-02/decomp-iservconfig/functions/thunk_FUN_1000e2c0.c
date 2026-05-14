void __fastcall thunk_FUN_1000e2c0(int *param_1)

{
  void *pvVar1;
  code *pcVar2;
  void *pvVar3;
  
  if ((char)param_1[0xc] != -1) {
    if ((char)param_1[0xc] == '\0') {
      FUN_1000bb10(param_1);
      return;
    }
    if (0xf < (uint)param_1[7]) {
      pvVar1 = (void *)param_1[2];
      pvVar3 = pvVar1;
      if ((0xfff < param_1[7] + 1U) &&
         (pvVar3 = *(void **)((int)pvVar1 + -4), 0x1f < (uint)((int)pvVar1 + (-4 - (int)pvVar3)))) {
        FUN_10032f7f();
        pcVar2 = (code *)swi(3);
        (*pcVar2)();
        return;
      }
      FUN_1002e346(pvVar3);
    }
    param_1[6] = 0;
    param_1[7] = 0xf;
    *(undefined1 *)(param_1 + 2) = 0;
  }
  return;
}


// FUNCTION_END

// FUNCTION_START: thunk_FUN_1000e210 @ 1000bde0