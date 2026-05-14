undefined8 *
FUN_1400131d0(undefined8 *param_1,ulonglong param_2,undefined8 param_3,undefined8 *param_4,
             longlong param_5)

{
  ulonglong uVar1;
  undefined2 *puVar2;
  longlong lVar3;
  ulonglong uVar4;
  undefined8 *puVar5;
  code *pcVar6;
  void *pvVar7;
  ulonglong uVar8;
  undefined8 *puVar9;
  ulonglong uVar10;
  
  lVar3 = param_1[2];
  if (0x7ffffffffffffffeU - lVar3 < param_2) {
    FUN_140001a20();
    pcVar6 = (code *)swi(3);
    puVar9 = (undefined8 *)(*pcVar6)();
    return puVar9;
  }
  uVar4 = param_1[3];
  uVar8 = param_2 + lVar3 | 7;
  uVar10 = 0x7ffffffffffffffe;
  if (((uVar8 < 0x7fffffffffffffff) && (uVar4 <= 0x7ffffffffffffffe - (uVar4 >> 1))) &&
     (uVar1 = (uVar4 >> 1) + uVar4, uVar10 = uVar8, uVar8 < uVar1)) {
    uVar10 = uVar1;
  }
  uVar8 = uVar10 + 1;
  if (uVar10 == 0xffffffffffffffff) {
    uVar8 = 0xffffffffffffffff;
  }
  if (0x7fffffffffffffff < uVar8) {
LAB_140013377:
    FUN_140001670();
    pcVar6 = (code *)swi(3);
    puVar9 = (undefined8 *)(*pcVar6)();
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
    if (uVar8 + 0x27 <= uVar8) goto LAB_140013377;
    pvVar7 = operator_new(uVar8 + 0x27);
    if (pvVar7 == (void *)0x0) goto LAB_140013371;
    puVar9 = (undefined8 *)((longlong)pvVar7 + 0x27U & 0xffffffffffffffe0);
    puVar9[-1] = pvVar7;
  }
  uVar8 = lVar3 * 2;
  param_1[2] = param_2 + lVar3;
  param_1[3] = uVar10;
  puVar2 = (undefined2 *)((longlong)puVar9 + (param_5 + lVar3) * 2);
  if (uVar4 < 8) {
    FUN_1400316b0(puVar9,param_1,uVar8);
    FUN_1400316b0((undefined8 *)(uVar8 + (longlong)puVar9),param_4,param_5 * 2);
    *puVar2 = 0;
  }
  else {
    puVar5 = (undefined8 *)*param_1;
    FUN_1400316b0(puVar9,puVar5,uVar8);
    FUN_1400316b0((undefined8 *)(uVar8 + (longlong)puVar9),param_4,param_5 * 2);
    *puVar2 = 0;
    if ((0xfff < uVar4 * 2 + 2) && (0x1f < (ulonglong)((longlong)puVar5 + (-8 - puVar5[-1])))) {
LAB_140013371:
      FUN_140035d28();
      pcVar6 = (code *)swi(3);
      puVar9 = (undefined8 *)(*pcVar6)();
      return puVar9;
    }
    FUN_14002f180();
  }
  *param_1 = puVar9;
  return param_1;
}


// FUNCTION_END

// FUNCTION_START: FUN_140013390 @ 140013390