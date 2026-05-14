undefined8 *
FUN_140013620(undefined8 *param_1,ulonglong param_2,undefined8 param_3,longlong param_4,
             undefined2 param_5)

{
  ulonglong uVar1;
  longlong lVar2;
  ulonglong uVar3;
  undefined8 *puVar4;
  code *pcVar5;
  void *pvVar6;
  longlong lVar7;
  ulonglong uVar8;
  undefined8 *puVar9;
  ulonglong uVar10;
  undefined2 *puVar11;
  
  lVar2 = param_1[2];
  if (0x7ffffffffffffffeU - lVar2 < param_2) {
    FUN_140001a20();
    pcVar5 = (code *)swi(3);
    puVar9 = (undefined8 *)(*pcVar5)();
    return puVar9;
  }
  uVar3 = param_1[3];
  uVar8 = param_2 + lVar2 | 7;
  uVar10 = 0x7ffffffffffffffe;
  if (((uVar8 < 0x7fffffffffffffff) && (uVar3 <= 0x7ffffffffffffffe - (uVar3 >> 1))) &&
     (uVar1 = (uVar3 >> 1) + uVar3, uVar10 = uVar8, uVar8 < uVar1)) {
    uVar10 = uVar1;
  }
  uVar8 = uVar10 + 1;
  if (uVar10 == 0xffffffffffffffff) {
    uVar8 = 0xffffffffffffffff;
  }
  if (0x7fffffffffffffff < uVar8) {
LAB_1400137cc:
    FUN_140001670();
    pcVar5 = (code *)swi(3);
    puVar9 = (undefined8 *)(*pcVar5)();
    return puVar9;
  }
  uVar8 = uVar8 * 2;
  puVar9 = (undefined8 *)0x0;
  if (uVar8 < 0x1000) {
    if (uVar8 != 0) {
      puVar9 = (undefined8 *)operator_new(uVar8);
    }
  }
  else {
    if (uVar8 + 0x27 <= uVar8) goto LAB_1400137cc;
    pvVar6 = operator_new(uVar8 + 0x27);
    if (pvVar6 == (void *)0x0) goto LAB_1400137c6;
    puVar9 = (undefined8 *)((longlong)pvVar6 + 0x27U & 0xffffffffffffffe0);
    puVar9[-1] = pvVar6;
  }
  param_1[3] = uVar10;
  uVar10 = lVar2 * 2;
  param_1[2] = param_2 + lVar2;
  puVar11 = (undefined2 *)(uVar10 + (longlong)puVar9);
  if (uVar3 < 8) {
    FUN_1400316b0(puVar9,param_1,uVar10);
    lVar7 = param_4;
    if (param_4 != 0) {
      for (; lVar7 != 0; lVar7 = lVar7 + -1) {
        *puVar11 = param_5;
        puVar11 = puVar11 + 1;
      }
    }
    *(undefined2 *)((longlong)puVar9 + (param_4 + lVar2) * 2) = 0;
  }
  else {
    puVar4 = (undefined8 *)*param_1;
    FUN_1400316b0(puVar9,puVar4,uVar10);
    lVar7 = param_4;
    if (param_4 != 0) {
      for (; lVar7 != 0; lVar7 = lVar7 + -1) {
        *puVar11 = param_5;
        puVar11 = puVar11 + 1;
      }
    }
    *(undefined2 *)((longlong)puVar9 + (param_4 + lVar2) * 2) = 0;
    if ((0xfff < uVar3 * 2 + 2) && (0x1f < (ulonglong)((longlong)puVar4 + (-8 - puVar4[-1])))) {
LAB_1400137c6:
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

// FUNCTION_START: FUN_1400137e0 @ 1400137e0