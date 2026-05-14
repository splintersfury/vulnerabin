void FUN_140010a90(longlong param_1)

{
  longlong lVar1;
  undefined8 *puVar2;
  code *pcVar3;
  
  lVar1 = *(longlong *)(param_1 + 0x18);
  if ((0xfff < (*(longlong *)(param_1 + 0x20) - lVar1 & 0xfffffffffffffff8U)) &&
     (0x1f < (lVar1 - *(longlong *)(lVar1 + -8)) - 8U)) {
    FUN_140035d28();
    pcVar3 = (code *)swi(3);
    (*pcVar3)();
    return;
  }
  FUN_14002f180();
  *(undefined8 *)(param_1 + 0x18) = 0;
  *(undefined8 *)(param_1 + 0x20) = 0;
  *(undefined8 *)(param_1 + 0x28) = 0;
  puVar2 = *(undefined8 **)(param_1 + 8);
  *(undefined8 *)puVar2[1] = 0;
  puVar2 = (undefined8 *)*puVar2;
  while (puVar2 != (undefined8 *)0x0) {
    puVar2 = (undefined8 *)*puVar2;
    FUN_14002f180();
  }
  FUN_14002f180();
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_140010b40 @ 140010b40