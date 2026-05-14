void FUN_14000e4b0(longlong *param_1)

{
  code *pcVar1;
  ulonglong uVar2;
  void *pvVar3;
  ulonglong uVar4;
  undefined8 *puVar5;
  
  if (7 < (ulonglong)param_1[3]) {
    uVar4 = param_1[2];
    if (uVar4 < 8) {
      puVar5 = (undefined8 *)*param_1;
      FUN_1400316b0(param_1,puVar5,uVar4 * 2 + 2);
      if ((0xfff < param_1[3] * 2 + 2U) &&
         (0x1f < (ulonglong)((longlong)puVar5 + (-8 - puVar5[-1])))) {
LAB_14000e618:
        FUN_140035d28();
        pcVar1 = (code *)swi(3);
        (*pcVar1)();
        return;
      }
      FUN_14002f180();
      param_1[3] = 7;
    }
    else {
      uVar4 = uVar4 | 7;
      if (0x7ffffffffffffffe < uVar4) {
        uVar4 = 0x7ffffffffffffffe;
      }
      if (uVar4 < (ulonglong)param_1[3]) {
        if (0x7fffffffffffffff < uVar4 + 1) {
LAB_14000e61e:
          FUN_140001670();
          pcVar1 = (code *)swi(3);
          (*pcVar1)();
          return;
        }
        uVar2 = (uVar4 + 1) * 2;
        if (uVar2 < 0x1000) {
          if (uVar2 == 0) {
            puVar5 = (undefined8 *)0x0;
          }
          else {
            puVar5 = (undefined8 *)operator_new(uVar2);
          }
        }
        else {
          if (uVar2 + 0x27 <= uVar2) goto LAB_14000e61e;
          pvVar3 = operator_new(uVar2 + 0x27);
          if (pvVar3 == (void *)0x0) goto LAB_14000e618;
          puVar5 = (undefined8 *)((longlong)pvVar3 + 0x27U & 0xffffffffffffffe0);
          puVar5[-1] = pvVar3;
        }
        FUN_1400316b0(puVar5,(undefined8 *)*param_1,param_1[2] * 2 + 2);
        if ((param_1[3] * 2 + 2U < 0x1000) ||
           ((*param_1 - *(longlong *)(*param_1 + -8)) - 8U < 0x20)) {
          FUN_14002f180();
          *param_1 = (longlong)puVar5;
          param_1[3] = uVar4;
          return;
        }
        goto LAB_14000e618;
      }
    }
  }
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_14000e630 @ 14000e630