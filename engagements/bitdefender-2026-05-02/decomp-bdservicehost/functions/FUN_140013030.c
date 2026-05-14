undefined8 *
FUN_140013030(undefined8 *param_1,undefined8 param_2,undefined8 param_3,undefined2 param_4)

{
  ulonglong uVar1;
  longlong lVar2;
  ulonglong uVar3;
  undefined8 *puVar4;
  code *pcVar5;
  void *pvVar6;
  ulonglong uVar7;
  ulonglong uVar8;
  undefined8 *puVar9;
  
  lVar2 = param_1[2];
  if (lVar2 == 0x7ffffffffffffffe) {
    FUN_140001a20();
    pcVar5 = (code *)swi(3);
    puVar9 = (undefined8 *)(*pcVar5)();
    return puVar9;
  }
  uVar3 = param_1[3];
  uVar7 = lVar2 + 1U | 7;
  uVar8 = 0x7ffffffffffffffe;
  if (((uVar7 < 0x7fffffffffffffff) && (uVar3 <= 0x7ffffffffffffffe - (uVar3 >> 1))) &&
     (uVar1 = (uVar3 >> 1) + uVar3, uVar8 = uVar7, uVar7 < uVar1)) {
    uVar8 = uVar1;
  }
  uVar7 = uVar8 + 1;
  if (uVar8 == 0xffffffffffffffff) {
    uVar7 = 0xffffffffffffffff;
  }
  if (0x7fffffffffffffff < uVar7) {
LAB_1400131b8:
    FUN_140001670();
    pcVar5 = (code *)swi(3);
    puVar9 = (undefined8 *)(*pcVar5)();
    return puVar9;
  }
  uVar7 = uVar7 * 2;
  puVar9 = (undefined8 *)0x0;
  if (uVar7 < 0x1000) {
    if (uVar7 != 0) {
      puVar9 = (undefined8 *)operator_new(uVar7);
    }
  }
  else {
    if (uVar7 + 0x27 <= uVar7) goto LAB_1400131b8;
    pvVar6 = operator_new(uVar7 + 0x27);
    if (pvVar6 == (void *)0x0) goto LAB_1400131b2;
    puVar9 = (undefined8 *)((longlong)pvVar6 + 0x27U & 0xffffffffffffffe0);
    puVar9[-1] = pvVar6;
  }
  uVar7 = lVar2 * 2;
  param_1[2] = lVar2 + 1U;
  param_1[3] = uVar8;
  if (uVar3 < 8) {
    FUN_1400316b0(puVar9,param_1,uVar7);
    *(undefined2 *)(uVar7 + (longlong)puVar9) = param_4;
    *(undefined2 *)(uVar7 + 2 + (longlong)puVar9) = 0;
  }
  else {
    puVar4 = (undefined8 *)*param_1;
    FUN_1400316b0(puVar9,puVar4,uVar7);
    *(undefined2 *)(uVar7 + (longlong)puVar9) = param_4;
    *(undefined2 *)(uVar7 + 2 + (longlong)puVar9) = 0;
    if ((0xfff < uVar3 * 2 + 2) && (0x1f < (ulonglong)((longlong)puVar4 + (-8 - puVar4[-1])))) {
LAB_1400131b2:
      FUN_140035d28();
      pcVar5 = (code *)swi(3);
      puVar9 = (undefined8 *)(*pcVar5)();
      return puVar9;
    }
    FUN_14002f180();
  }
  *param_1 = puVar9;
  return param_1;
}


// FUNCTION_END

// FUNCTION_START: FUN_1400131d0 @ 1400131d0