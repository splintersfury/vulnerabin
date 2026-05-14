void FUN_14000d4e0(longlong *param_1)

{
  longlong lVar1;
  longlong lVar2;
  code *pcVar3;
  longlong lVar4;
  
  lVar4 = *param_1;
  if (lVar4 != 0) {
    lVar1 = param_1[1];
    if (lVar4 != lVar1) {
      do {
        lVar2 = *(longlong *)(lVar4 + 0x38);
        if (lVar2 != 0) {
          (*(code *)PTR__guard_dispatch_icall_14005b538)(lVar2,lVar2 != lVar4);
          *(undefined8 *)(lVar4 + 0x38) = 0;
        }
        lVar4 = lVar4 + 0x40;
      } while (lVar4 != lVar1);
      lVar4 = *param_1;
    }
    if ((0xfff < (param_1[2] - lVar4 & 0xffffffffffffffc0U)) &&
       (0x1f < (lVar4 - *(longlong *)(lVar4 + -8)) - 8U)) {
      FUN_140035d28();
      pcVar3 = (code *)swi(3);
      (*pcVar3)();
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

// FUNCTION_START: FUN_14000d5a0 @ 14000d5a0