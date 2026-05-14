undefined8 * FUN_14000e990(undefined8 *param_1,undefined8 *param_2)

{
  ulonglong uVar1;
  ulonglong uVar2;
  code *pcVar3;
  undefined8 uVar4;
  void *pvVar5;
  undefined8 *puVar6;
  ulonglong uVar7;
  
  puVar6 = (undefined8 *)0x0;
  *param_1 = 0;
  param_1[2] = 0;
  param_1[3] = 0;
  uVar2 = param_2[2];
  if (0xf < (ulonglong)param_2[3]) {
    param_2 = (undefined8 *)*param_2;
  }
  if (uVar2 < 0x10) {
    uVar4 = param_2[1];
    uVar7 = 0xf;
    *param_1 = *param_2;
    param_1[1] = uVar4;
  }
  else {
    uVar7 = uVar2 | 0xf;
    if (0x7fffffffffffffff < uVar7) {
      uVar7 = 0x7fffffffffffffff;
    }
    uVar1 = uVar7 + 1;
    if (uVar1 < 0x1000) {
      if (uVar1 != 0) {
        puVar6 = (undefined8 *)operator_new(uVar1);
      }
    }
    else {
      if (uVar7 + 0x28 <= uVar1) {
        FUN_140001670();
        pcVar3 = (code *)swi(3);
        puVar6 = (undefined8 *)(*pcVar3)();
        return puVar6;
      }
      pvVar5 = operator_new(uVar7 + 0x28);
      if (pvVar5 == (void *)0x0) {
        FUN_140035d28();
        pcVar3 = (code *)swi(3);
        puVar6 = (undefined8 *)(*pcVar3)();
        return puVar6;
      }
      puVar6 = (undefined8 *)((longlong)pvVar5 + 0x27U & 0xffffffffffffffe0);
      puVar6[-1] = pvVar5;
    }
    *param_1 = puVar6;
    FUN_1400316b0(puVar6,param_2,uVar2 + 1);
  }
  param_1[2] = uVar2;
  param_1[3] = uVar7;
  return param_1;
}


// FUNCTION_END

// FUNCTION_START: FUN_14000ea70 @ 14000ea70