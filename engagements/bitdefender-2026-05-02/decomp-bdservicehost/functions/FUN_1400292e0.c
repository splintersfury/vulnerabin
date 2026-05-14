undefined1 * FUN_1400292e0(longlong *param_1,undefined1 *param_2,undefined8 *param_3)

{
  ulonglong uVar1;
  longlong lVar2;
  code *pcVar3;
  longlong lVar4;
  void *pvVar5;
  ulonglong uVar6;
  __uint64 _Var7;
  undefined1 *puVar8;
  undefined1 *puVar9;
  undefined1 *puVar10;
  ulonglong uVar11;
  undefined1 *puVar12;
  undefined1 *puVar13;
  
  lVar2 = *param_1;
  lVar4 = param_1[1] - lVar2 >> 4;
  if (lVar4 == 0xfffffffffffffff) {
    FUN_140014450();
    pcVar3 = (code *)swi(3);
    puVar13 = (undefined1 *)(*pcVar3)();
    return puVar13;
  }
  uVar6 = param_1[2] - lVar2 >> 4;
  uVar1 = lVar4 + 1;
  if (uVar6 <= 0xfffffffffffffff - (uVar6 >> 1)) {
    uVar6 = (uVar6 >> 1) + uVar6;
    uVar11 = uVar1;
    if (uVar1 <= uVar6) {
      uVar11 = uVar6;
    }
    if (uVar11 < 0x1000000000000000) {
      puVar13 = (undefined1 *)0x0;
      _Var7 = uVar11 * 0x10;
      if (_Var7 < 0x1000) {
        if (_Var7 != 0) {
          puVar13 = (undefined1 *)operator_new(_Var7);
        }
      }
      else {
        if (_Var7 + 0x27 <= _Var7) goto LAB_1400294a3;
        pvVar5 = operator_new(_Var7 + 0x27);
        if (pvVar5 == (void *)0x0) {
          FUN_140035d28();
          pcVar3 = (code *)swi(3);
          puVar13 = (undefined1 *)(*pcVar3)();
          return puVar13;
        }
        puVar13 = (undefined1 *)((longlong)pvVar5 + 0x27U & 0xffffffffffffffe0);
        *(void **)(puVar13 + -8) = pvVar5;
      }
      puVar10 = puVar13 + ((longlong)param_2 - lVar2 & 0xfffffffffffffff0);
      *puVar10 = 0;
      *(undefined8 *)(puVar10 + 8) = 0;
      *(undefined8 *)(puVar10 + 8) = *param_3;
      *puVar10 = 7;
      puVar12 = (undefined1 *)param_1[1];
      puVar8 = (undefined1 *)*param_1;
      puVar9 = puVar13;
      if (param_2 == puVar12) {
        for (; puVar8 != puVar12; puVar8 = puVar8 + 0x10) {
          *puVar9 = *puVar8;
          *(undefined8 *)(puVar9 + 8) = *(undefined8 *)(puVar8 + 8);
          *puVar8 = 0;
          *(undefined8 *)(puVar8 + 8) = 0;
          puVar9 = puVar9 + 0x10;
        }
      }
      else {
        if (puVar8 != param_2) {
          do {
            *puVar9 = *puVar8;
            *(undefined8 *)(puVar9 + 8) = *(undefined8 *)(puVar8 + 8);
            *puVar8 = 0;
            *(undefined8 *)(puVar8 + 8) = 0;
            puVar8 = puVar8 + 0x10;
            puVar9 = puVar9 + 0x10;
          } while (puVar8 != param_2);
          puVar12 = (undefined1 *)param_1[1];
        }
        puVar8 = param_2;
        if (param_2 != puVar12) {
          do {
            puVar8[(longlong)(puVar10 + (0x10 - (longlong)param_2))] = *puVar8;
            *(undefined8 *)(puVar8 + (longlong)(puVar10 + (0x18 - (longlong)param_2))) =
                 *(undefined8 *)(puVar8 + 8);
            *puVar8 = 0;
            *(undefined8 *)(puVar8 + 8) = 0;
            puVar8 = puVar8 + 0x10;
          } while (puVar8 != puVar12);
        }
      }
      FUN_140029e80(param_1,(longlong)puVar13,uVar1,uVar11);
      return puVar10;
    }
  }
LAB_1400294a3:
  FUN_140001670();
  pcVar3 = (code *)swi(3);
  puVar13 = (undefined1 *)(*pcVar3)();
  return puVar13;
}


// FUNCTION_END

// FUNCTION_START: FUN_1400294b0 @ 1400294b0