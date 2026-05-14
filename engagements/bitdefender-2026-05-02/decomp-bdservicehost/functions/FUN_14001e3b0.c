void FUN_14001e3b0(longlong *param_1)

{
  longlong lVar1;
  code *pcVar2;
  
  lVar1 = *param_1;
  if (lVar1 != 0) {
    if ((0xfff < (param_1[2] - lVar1 & 0xfffffffffffffff8U)) &&
       (0x1f < (lVar1 - *(longlong *)(lVar1 + -8)) - 8U)) {
      FUN_140035d28();
      pcVar2 = (code *)swi(3);
      (*pcVar2)();
      return;
    }
    FUN_14002f180();
    *param_1 = 0;
    param_1[1] = 0;
    param_1[2] = 0;
  }
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_14001e410 @ 14001e410