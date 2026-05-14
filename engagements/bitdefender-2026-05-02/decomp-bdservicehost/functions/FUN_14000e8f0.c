void FUN_14000e8f0(longlong *param_1)

{
  code *pcVar1;
  
  if (0xf < (ulonglong)param_1[3]) {
    if ((0xfff < param_1[3] + 1U) && (0x1f < (*param_1 - *(longlong *)(*param_1 + -8)) - 8U)) {
      FUN_140035d28();
      pcVar1 = (code *)swi(3);
      (*pcVar1)();
      return;
    }
    FUN_14002f180();
  }
  param_1[2] = 0;
  param_1[3] = 0xf;
  *(undefined1 *)param_1 = 0;
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_14000e950 @ 14000e950