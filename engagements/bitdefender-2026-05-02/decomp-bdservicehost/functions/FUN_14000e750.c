undefined8 * FUN_14000e750(undefined8 *param_1,undefined8 *param_2)

{
  ulonglong uVar1;
  code *pcVar2;
  ulonglong uVar3;
  undefined8 uVar4;
  void *pvVar5;
  undefined8 *puVar6;
  ulonglong uVar7;
  
  puVar6 = (undefined8 *)0x0;
  *param_1 = 0;
  param_1[2] = 0;
  param_1[3] = 0;
  uVar1 = param_2[2];
  if (7 < (ulonglong)param_2[3]) {
    param_2 = (undefined8 *)*param_2;
  }
  if (uVar1 < 8) {
    uVar4 = param_2[1];
    uVar7 = 7;
    *param_1 = *param_2;
    param_1[1] = uVar4;
  }
  else {
    uVar7 = uVar1 | 7;
    if (0x7ffffffffffffffe < uVar7) {
      uVar7 = 0x7ffffffffffffffe;
    }
    if (0x7fffffffffffffff < uVar7 + 1) {
LAB_14000e83c:
      FUN_140001670();
      pcVar2 = (code *)swi(3);
      puVar6 = (undefined8 *)(*pcVar2)();
      return puVar6;
    }
    uVar3 = (uVar7 + 1) * 2;
    if (uVar3 < 0x1000) {
      if (uVar3 != 0) {
        puVar6 = (undefined8 *)operator_new(uVar3);
      }
    }
    else {
      if (uVar3 + 0x27 <= uVar3) goto LAB_14000e83c;
      pvVar5 = operator_new(uVar3 + 0x27);
      if (pvVar5 == (void *)0x0) {
        FUN_140035d28();
        pcVar2 = (code *)swi(3);
        puVar6 = (undefined8 *)(*pcVar2)();
        return puVar6;
      }
      puVar6 = (undefined8 *)((longlong)pvVar5 + 0x27U & 0xffffffffffffffe0);
      puVar6[-1] = pvVar5;
    }
    *param_1 = puVar6;
    FUN_1400316b0(puVar6,param_2,uVar1 * 2 + 2);
  }
  param_1[2] = uVar1;
  param_1[3] = uVar7;
  return param_1;
}


// FUNCTION_END

// FUNCTION_START: FUN_14000e850 @ 14000e850