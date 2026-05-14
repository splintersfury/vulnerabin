void FUN_14001e240(longlong param_1)

{
  longlong lVar1;
  code *pcVar2;
  
  lVar1 = *(longlong *)(param_1 + 8);
  if (lVar1 != 0) {
    if ((0xfff < (*(longlong *)(param_1 + 0x18) - lVar1 & 0xfffffffffffffff8U)) &&
       (0x1f < (lVar1 - *(longlong *)(lVar1 + -8)) - 8U)) {
      FUN_140035d28();
      pcVar2 = (code *)swi(3);
      (*pcVar2)();
      return;
    }
    FUN_14002f180();
    *(undefined8 *)(param_1 + 8) = 0;
    *(undefined8 *)(param_1 + 0x10) = 0;
    *(undefined8 *)(param_1 + 0x18) = 0;
  }
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_14001e2a0 @ 14001e2a0