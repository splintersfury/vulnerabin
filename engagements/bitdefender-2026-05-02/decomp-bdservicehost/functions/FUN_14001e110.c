void FUN_14001e110(longlong param_1)

{
  longlong lVar1;
  code *pcVar2;
  
  FUN_14001cf70((char *)(param_1 + 0xb8));
  lVar1 = *(longlong *)(param_1 + 0xa8);
  if (lVar1 != 0) {
    (*(code *)PTR__guard_dispatch_icall_14005b538)(lVar1,lVar1 != param_1 + 0x70);
    *(undefined8 *)(param_1 + 0xa8) = 0;
  }
  lVar1 = *(longlong *)(param_1 + 0x40);
  if (lVar1 != 0) {
    if ((0xfff < (*(longlong *)(param_1 + 0x50) - lVar1 & 0xfffffffffffffffcU)) &&
       (0x1f < (lVar1 - *(longlong *)(lVar1 + -8)) - 8U)) goto LAB_14001e23a;
    FUN_14002f180();
    *(undefined8 *)(param_1 + 0x40) = 0;
    *(undefined8 *)(param_1 + 0x48) = 0;
    *(undefined8 *)(param_1 + 0x50) = 0;
  }
  lVar1 = *(longlong *)(param_1 + 0x20);
  if (lVar1 != 0) {
    if ((0xfff < (*(longlong *)(param_1 + 0x30) - lVar1 & 0xfffffffffffffffcU)) &&
       (0x1f < (lVar1 - *(longlong *)(lVar1 + -8)) - 8U)) goto LAB_14001e23a;
    FUN_14002f180();
    *(undefined8 *)(param_1 + 0x20) = 0;
    *(undefined8 *)(param_1 + 0x28) = 0;
    *(undefined8 *)(param_1 + 0x30) = 0;
  }
  lVar1 = *(longlong *)(param_1 + 8);
  if (lVar1 != 0) {
    if ((0xfff < (*(longlong *)(param_1 + 0x18) - lVar1 & 0xfffffffffffffff8U)) &&
       (0x1f < (lVar1 - *(longlong *)(lVar1 + -8)) - 8U)) {
LAB_14001e23a:
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

// FUNCTION_START: FUN_14001e240 @ 14001e240