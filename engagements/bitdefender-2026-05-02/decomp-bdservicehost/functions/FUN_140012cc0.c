longlong FUN_140012cc0(longlong *param_1,undefined8 *param_2,longlong param_3)

{
  longlong lVar1;
  longlong lVar2;
  code *pcVar3;
  void *pvVar4;
  undefined8 uVar5;
  longlong lVar6;
  ulonglong uVar7;
  __uint64 _Var8;
  undefined8 *puVar9;
  undefined8 *puVar10;
  void *pvVar11;
  longlong lVar12;
  ulonglong uVar13;
  ulonglong uVar14;
  
  lVar6 = *param_1;
  lVar12 = param_1[1] - lVar6 >> 6;
  if (lVar12 == 0x3ffffffffffffff) {
    FUN_140014450();
    pcVar3 = (code *)swi(3);
    lVar6 = (*pcVar3)();
    return lVar6;
  }
  uVar13 = lVar12 + 1;
  uVar7 = param_1[2] - lVar6 >> 6;
  if (0x3ffffffffffffff - (uVar7 >> 1) < uVar7) {
    uVar14 = 0xffffffffffffffc0;
    _Var8 = 0xffffffffffffffe7;
LAB_140012d6f:
    pvVar4 = operator_new(_Var8);
    if (pvVar4 == (void *)0x0) goto LAB_140012ee0;
    pvVar11 = (void *)((longlong)pvVar4 + 0x27U & 0xffffffffffffffe0);
    *(void **)((longlong)pvVar11 + -8) = pvVar4;
  }
  else {
    uVar7 = (uVar7 >> 1) + uVar7;
    uVar14 = uVar13;
    if (uVar13 <= uVar7) {
      uVar14 = uVar7;
    }
    if (0x3ffffffffffffff < uVar14) {
LAB_140012ed4:
      FUN_140001670();
      pcVar3 = (code *)swi(3);
      lVar6 = (*pcVar3)();
      return lVar6;
    }
    uVar14 = uVar14 * 0x40;
    if (0xfff < uVar14) {
      _Var8 = uVar14 + 0x27;
      if (_Var8 <= uVar14) goto LAB_140012ed4;
      goto LAB_140012d6f;
    }
    if (uVar14 == 0) {
      pvVar11 = (void *)0x0;
    }
    else {
      pvVar11 = operator_new(uVar14);
    }
  }
  lVar6 = ((longlong)param_2 - lVar6 & 0xffffffffffffffc0U) + (longlong)pvVar11;
  *(undefined8 *)(lVar6 + 0x38) = 0;
  if (*(longlong *)(param_3 + 0x38) != 0) {
    uVar5 = (*(code *)PTR__guard_dispatch_icall_14005b538)(*(longlong *)(param_3 + 0x38),lVar6);
    *(undefined8 *)(lVar6 + 0x38) = uVar5;
  }
  puVar10 = (undefined8 *)param_1[1];
  puVar9 = (undefined8 *)*param_1;
  pvVar4 = pvVar11;
  if (param_2 != puVar10) {
    FUN_140014a20((undefined8 *)*param_1,param_2,(longlong)pvVar11);
    puVar10 = (undefined8 *)param_1[1];
    puVar9 = param_2;
    pvVar4 = (void *)(lVar6 + 0x40);
  }
  FUN_140014a20(puVar9,puVar10,(longlong)pvVar4);
  lVar12 = *param_1;
  if (lVar12 != 0) {
    lVar1 = param_1[1];
    if (lVar12 != lVar1) {
      do {
        lVar2 = *(longlong *)(lVar12 + 0x38);
        if (lVar2 != 0) {
          (*(code *)PTR__guard_dispatch_icall_14005b538)(lVar2,lVar2 != lVar12);
          *(undefined8 *)(lVar12 + 0x38) = 0;
        }
        lVar12 = lVar12 + 0x40;
      } while (lVar12 != lVar1);
      lVar12 = *param_1;
    }
    if ((0xfff < (param_1[2] - lVar12 & 0xffffffffffffffc0U)) &&
       (0x1f < (lVar12 - *(longlong *)(lVar12 + -8)) - 8U)) {
LAB_140012ee0:
      FUN_140035d28();
      pcVar3 = (code *)swi(3);
      lVar6 = (*pcVar3)();
      return lVar6;
    }
    FUN_14002f180();
  }
  *param_1 = (longlong)pvVar11;
  param_1[1] = (longlong)(uVar13 * 0x40 + (longlong)pvVar11);
  param_1[2] = uVar14 + (longlong)pvVar11;
  return lVar6;
}


// FUNCTION_END

// FUNCTION_START: FUN_140012ef0 @ 140012ef0