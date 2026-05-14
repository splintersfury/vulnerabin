void __fastcall FUN_1000f080(int *param_1)

{
  void *pvVar1;
  code *pcVar2;
  void *pvVar3;
  
  if ((char)param_1[8] != -1) {
    if ((char)param_1[8] != '\0') {
      if (0xf < (uint)param_1[7]) {
        pvVar1 = (void *)param_1[2];
        pvVar3 = pvVar1;
        if ((0xfff < param_1[7] + 1U) &&
           (pvVar3 = *(void **)((int)pvVar1 + -4), 0x1f < (uint)((int)pvVar1 + (-4 - (int)pvVar3))))
        goto LAB_1000f11c;
        FUN_1002e346(pvVar3);
      }
      param_1[6] = 0;
      param_1[7] = 0xf;
      *(undefined1 *)(param_1 + 2) = 0;
      return;
    }
    if (0xf < (uint)param_1[5]) {
      pvVar1 = (void *)*param_1;
      pvVar3 = pvVar1;
      if ((0xfff < param_1[5] + 1U) &&
         (pvVar3 = *(void **)((int)pvVar1 + -4), 0x1f < (uint)((int)pvVar1 + (-4 - (int)pvVar3)))) {
LAB_1000f11c:
        FUN_10032f7f();
        pcVar2 = (code *)swi(3);
        (*pcVar2)();
        return;
      }
      FUN_1002e346(pvVar3);
    }
    param_1[4] = 0;
    param_1[5] = 0xf;
    *(undefined1 *)param_1 = 0;
  }
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_1000f130 @ 1000f130