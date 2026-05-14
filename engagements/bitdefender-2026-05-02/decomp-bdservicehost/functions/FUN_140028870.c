void FUN_140028870(longlong param_1)

{
  longlong lVar1;
  code *pcVar2;
  
  lVar1 = *(longlong *)(param_1 + 8);
  if (lVar1 != 0) {
    if (0xf < *(ulonglong *)(lVar1 + 0x28)) {
      if ((0xfff < *(ulonglong *)(lVar1 + 0x28) + 1) &&
         (0x1f < (*(longlong *)(lVar1 + 0x10) - *(longlong *)(*(longlong *)(lVar1 + 0x10) + -8)) -
                 8U)) {
        FUN_140035d28();
        pcVar2 = (code *)swi(3);
        (*pcVar2)();
        return;
      }
      FUN_14002f180();
    }
    *(undefined8 *)(lVar1 + 0x20) = 0;
    *(undefined8 *)(lVar1 + 0x28) = 0xf;
    *(undefined1 *)(lVar1 + 0x10) = 0;
  }
  if (*(longlong *)(param_1 + 8) != 0) {
    FUN_14002f180();
  }
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_140028900 @ 140028900