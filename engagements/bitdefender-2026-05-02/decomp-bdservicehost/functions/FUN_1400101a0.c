longlong * FUN_1400101a0(longlong *param_1,ulonglong param_2,undefined2 param_3)

{
  ulonglong uVar1;
  code *pcVar2;
  void *pvVar3;
  longlong *plVar4;
  ulonglong uVar5;
  ulonglong uVar6;
  ulonglong uVar7;
  longlong *plVar8;
  undefined2 *puVar9;
  undefined2 *puVar10;
  
  uVar5 = param_1[3];
  if (param_2 <= uVar5) {
    plVar4 = param_1;
    if (7 < uVar5) {
      plVar4 = (longlong *)*param_1;
    }
    param_1[2] = param_2;
    uVar5 = param_2;
    plVar8 = plVar4;
    if (param_2 != 0) {
      for (; uVar5 != 0; uVar5 = uVar5 - 1) {
        *(undefined2 *)plVar8 = param_3;
        plVar8 = (longlong *)((longlong)plVar8 + 2);
      }
    }
    *(undefined2 *)((longlong)plVar4 + param_2 * 2) = 0;
    return param_1;
  }
  if (0x7ffffffffffffffe < param_2) {
    FUN_140001a20();
    pcVar2 = (code *)swi(3);
    plVar4 = (longlong *)(*pcVar2)();
    return plVar4;
  }
  uVar6 = param_2 | 7;
  uVar7 = 0x7ffffffffffffffe;
  if (((uVar6 < 0x7fffffffffffffff) && (uVar5 <= 0x7ffffffffffffffe - (uVar5 >> 1))) &&
     (uVar1 = (uVar5 >> 1) + uVar5, uVar7 = uVar6, uVar6 < uVar1)) {
    uVar7 = uVar1;
  }
  uVar6 = uVar7 + 1;
  if (uVar7 == 0xffffffffffffffff) {
    uVar6 = 0xffffffffffffffff;
  }
  if (0x7fffffffffffffff < uVar6) {
LAB_14001032d:
    FUN_140001670();
    pcVar2 = (code *)swi(3);
    plVar4 = (longlong *)(*pcVar2)();
    return plVar4;
  }
  uVar6 = uVar6 * 2;
  puVar10 = (undefined2 *)0x0;
  if (uVar6 < 0x1000) {
    if (uVar6 != 0) {
      puVar10 = (undefined2 *)operator_new(uVar6);
    }
  }
  else {
    if (uVar6 + 0x27 <= uVar6) goto LAB_14001032d;
    pvVar3 = operator_new(uVar6 + 0x27);
    if (pvVar3 == (void *)0x0) goto LAB_140010327;
    puVar10 = (undefined2 *)((longlong)pvVar3 + 0x27U & 0xffffffffffffffe0);
    *(void **)(puVar10 + -4) = pvVar3;
  }
  param_1[2] = param_2;
  param_1[3] = uVar7;
  uVar7 = param_2;
  puVar9 = puVar10;
  if (param_2 != 0) {
    for (; uVar7 != 0; uVar7 = uVar7 - 1) {
      *puVar9 = param_3;
      puVar9 = puVar9 + 1;
    }
  }
  puVar10[param_2] = 0;
  if (7 < uVar5) {
    if ((0xfff < uVar5 * 2 + 2) && (0x1f < (*param_1 - *(longlong *)(*param_1 + -8)) - 8U)) {
LAB_140010327:
      FUN_140035d28();
      pcVar2 = (code *)swi(3);
      plVar4 = (longlong *)(*pcVar2)();
      return plVar4;
    }
    FUN_14002f180();
  }
  *param_1 = (longlong)puVar10;
  return param_1;
}


// FUNCTION_END

// FUNCTION_START: FUN_140010340 @ 140010340