void FUN_14002d150(longlong param_1)

{
  code *pcVar1;
  
  if (*(char *)(param_1 + 0x30) != '\0') {
    if (0xf < *(ulonglong *)(param_1 + 0x28)) {
      if ((0xfff < *(ulonglong *)(param_1 + 0x28) + 1) &&
         (0x1f < (*(longlong *)(param_1 + 0x10) - *(longlong *)(*(longlong *)(param_1 + 0x10) + -8))
                 - 8U)) {
        FUN_140035d28();
        pcVar1 = (code *)swi(3);
        (*pcVar1)();
        return;
      }
      FUN_14002f180();
    }
    *(undefined8 *)(param_1 + 0x20) = 0;
    *(undefined8 *)(param_1 + 0x28) = 0xf;
    *(undefined1 *)(param_1 + 0x10) = 0;
  }
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_14002d1c0 @ 14002d1c0