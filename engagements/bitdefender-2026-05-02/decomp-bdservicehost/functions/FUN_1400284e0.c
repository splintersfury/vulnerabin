undefined8 * FUN_1400284e0(longlong *param_1,undefined8 *param_2,undefined8 *param_3)

{
  ulonglong uVar1;
  undefined8 *puVar2;
  longlong lVar3;
  undefined8 *puVar4;
  code *pcVar5;
  longlong lVar6;
  void *pvVar7;
  ulonglong uVar8;
  undefined8 *puVar9;
  undefined8 *puVar10;
  ulonglong uVar11;
  
  lVar3 = *param_1;
  lVar6 = param_1[1] - lVar3 >> 3;
  if (lVar6 == 0x1fffffffffffffff) {
    FUN_140014450();
    pcVar5 = (code *)swi(3);
    puVar10 = (undefined8 *)(*pcVar5)();
    return puVar10;
  }
  uVar8 = param_1[2] - lVar3 >> 3;
  uVar1 = lVar6 + 1;
  if (0x1fffffffffffffff - (uVar8 >> 1) < uVar8) {
LAB_14002866d:
    FUN_140001670();
    pcVar5 = (code *)swi(3);
    puVar10 = (undefined8 *)(*pcVar5)();
    return puVar10;
  }
  uVar8 = (uVar8 >> 1) + uVar8;
  uVar11 = uVar1;
  if (uVar1 <= uVar8) {
    uVar11 = uVar8;
  }
  if (0x1fffffffffffffff < uVar11) goto LAB_14002866d;
  uVar8 = uVar11 * 8;
  if (uVar8 < 0x1000) {
    if (uVar8 == 0) {
      puVar10 = (undefined8 *)0x0;
    }
    else {
      puVar10 = (undefined8 *)operator_new(uVar8);
    }
  }
  else {
    if (uVar8 + 0x27 <= uVar8) goto LAB_14002866d;
    pvVar7 = operator_new(uVar8 + 0x27);
    if (pvVar7 == (void *)0x0) goto LAB_140028667;
    puVar10 = (undefined8 *)((longlong)pvVar7 + 0x27U & 0xffffffffffffffe0);
    puVar10[-1] = pvVar7;
  }
  puVar2 = puVar10 + ((longlong)param_2 - lVar3 >> 3);
  *puVar2 = *param_3;
  puVar4 = (undefined8 *)*param_1;
  if (param_2 == (undefined8 *)param_1[1]) {
    uVar8 = param_1[1] - (longlong)puVar4;
    puVar9 = puVar10;
    param_2 = puVar4;
  }
  else {
    FUN_1400316b0(puVar10,puVar4,(longlong)param_2 - (longlong)puVar4);
    puVar9 = puVar2 + 1;
    uVar8 = param_1[1] - (longlong)param_2;
  }
  FUN_1400316b0(puVar9,param_2,uVar8);
  lVar3 = *param_1;
  if (lVar3 != 0) {
    if ((0xfff < (param_1[2] - lVar3 & 0xfffffffffffffff8U)) &&
       (0x1f < (lVar3 - *(longlong *)(lVar3 + -8)) - 8U)) {
LAB_140028667:
      FUN_140035d28();
      pcVar5 = (code *)swi(3);
      puVar10 = (undefined8 *)(*pcVar5)();
      return puVar10;
    }
    FUN_14002f180();
  }
  *param_1 = (longlong)puVar10;
  param_1[1] = (longlong)(puVar10 + uVar1);
  param_1[2] = (longlong)(puVar10 + uVar11);
  return puVar2;
}


// FUNCTION_END

// FUNCTION_START: FUN_140028680 @ 140028680