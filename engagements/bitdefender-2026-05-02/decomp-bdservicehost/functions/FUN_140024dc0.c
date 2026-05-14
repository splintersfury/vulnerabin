undefined1 * FUN_140024dc0(longlong *param_1,undefined8 *param_2,undefined1 *param_3)

{
  ulonglong uVar1;
  longlong lVar2;
  undefined8 *puVar3;
  code *pcVar4;
  void *pvVar5;
  ulonglong uVar6;
  undefined8 *puVar7;
  ulonglong uVar8;
  undefined8 *puVar9;
  undefined1 *puVar10;
  
  lVar2 = *param_1;
  uVar8 = 0x7fffffffffffffff;
  if (param_1[1] - lVar2 == 0x7fffffffffffffff) {
    FUN_140014450();
    pcVar4 = (code *)swi(3);
    puVar10 = (undefined1 *)(*pcVar4)();
    return puVar10;
  }
  uVar6 = param_1[2] - lVar2;
  uVar1 = (param_1[1] - lVar2) + 1;
  if (0x7fffffffffffffff - (uVar6 >> 1) < uVar6) {
    uVar6 = 0x8000000000000026;
LAB_140024e28:
    pvVar5 = operator_new(uVar6);
    if (pvVar5 == (void *)0x0) goto LAB_140024f28;
    puVar9 = (undefined8 *)((longlong)pvVar5 + 0x27U & 0xffffffffffffffe0);
    puVar9[-1] = pvVar5;
  }
  else {
    uVar6 = (uVar6 >> 1) + uVar6;
    uVar8 = uVar1;
    if (uVar1 <= uVar6) {
      uVar8 = uVar6;
    }
    if (0xfff < uVar8) {
      uVar6 = uVar8 + 0x27;
      if (uVar6 <= uVar8) {
        FUN_140001670();
        pcVar4 = (code *)swi(3);
        puVar10 = (undefined1 *)(*pcVar4)();
        return puVar10;
      }
      goto LAB_140024e28;
    }
    if (uVar8 == 0) {
      puVar9 = (undefined8 *)0x0;
    }
    else {
      puVar9 = (undefined8 *)operator_new(uVar8);
    }
  }
  puVar10 = (undefined1 *)(((longlong)param_2 - lVar2) + (longlong)puVar9);
  *puVar10 = *param_3;
  puVar3 = (undefined8 *)*param_1;
  if (param_2 == (undefined8 *)param_1[1]) {
    uVar6 = param_1[1] - (longlong)puVar3;
    puVar7 = puVar9;
    param_2 = puVar3;
  }
  else {
    FUN_1400316b0(puVar9,puVar3,(longlong)param_2 - (longlong)puVar3);
    puVar7 = (undefined8 *)(puVar10 + 1);
    uVar6 = param_1[1] - (longlong)param_2;
  }
  FUN_1400316b0(puVar7,param_2,uVar6);
  lVar2 = *param_1;
  if (lVar2 != 0) {
    if ((0xfff < (ulonglong)(param_1[2] - lVar2)) &&
       (0x1f < (lVar2 - *(longlong *)(lVar2 + -8)) - 8U)) {
LAB_140024f28:
      FUN_140035d28();
      pcVar4 = (code *)swi(3);
      puVar10 = (undefined1 *)(*pcVar4)();
      return puVar10;
    }
    FUN_14002f180();
  }
  *param_1 = (longlong)puVar9;
  param_1[1] = (longlong)puVar9 + uVar1;
  param_1[2] = (longlong)puVar9 + uVar8;
  return puVar10;
}


// FUNCTION_END

// FUNCTION_START: FUN_140024f50 @ 140024f50