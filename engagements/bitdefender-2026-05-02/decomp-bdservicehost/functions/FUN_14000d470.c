void FUN_14000d470(longlong *param_1)

{
  code *pcVar1;
  
  if ((char)param_1[4] != '\0') {
    if (7 < (ulonglong)param_1[3]) {
      if ((0xfff < param_1[3] * 2 + 2U) && (0x1f < (*param_1 - *(longlong *)(*param_1 + -8)) - 8U))
      {
        FUN_140035d28();
        pcVar1 = (code *)swi(3);
        (*pcVar1)();
        return;
      }
      FUN_14002f180();
    }
    param_1[3] = 7;
    param_1[2] = 0;
    *(undefined2 *)param_1 = 0;
  }
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_14000d4e0 @ 14000d4e0