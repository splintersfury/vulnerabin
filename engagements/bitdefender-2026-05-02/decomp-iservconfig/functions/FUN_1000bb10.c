void __fastcall FUN_1000bb10(int *param_1)

{
  void *pvVar1;
  code *pcVar2;
  void *pvVar3;
  
  if (0xf < (uint)param_1[0xb]) {
    pvVar1 = (void *)param_1[6];
    pvVar3 = pvVar1;
    if ((0xfff < param_1[0xb] + 1U) &&
       (pvVar3 = *(void **)((int)pvVar1 + -4), 0x1f < (uint)((int)pvVar1 + (-4 - (int)pvVar3))))
    goto LAB_1000bb97;
    FUN_1002e346(pvVar3);
  }
  param_1[10] = 0;
  param_1[0xb] = 0xf;
  *(undefined1 *)(param_1 + 6) = 0;
  if (0xf < (uint)param_1[5]) {
    pvVar1 = (void *)*param_1;
    pvVar3 = pvVar1;
    if ((0xfff < param_1[5] + 1U) &&
       (pvVar3 = *(void **)((int)pvVar1 + -4), 0x1f < (uint)((int)pvVar1 + (-4 - (int)pvVar3)))) {
LAB_1000bb97:
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
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_1000bba0 @ 1000bba0

/* WARNING: Removing unreachable block (ram,0x1000bd46) */