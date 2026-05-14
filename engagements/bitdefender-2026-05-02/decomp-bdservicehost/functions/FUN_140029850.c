undefined1 * FUN_140029850(longlong *param_1,undefined1 *param_2,undefined1 *param_3)

{
  ulonglong uVar1;
  longlong lVar2;
  code *pcVar3;
  longlong lVar4;
  void *pvVar5;
  undefined1 *puVar6;
  ulonglong uVar7;
  __uint64 _Var8;
  undefined1 *puVar9;
  undefined1 *puVar10;
  ulonglong uVar11;
  undefined1 *puVar12;
  undefined1 *puVar13;
  undefined7 uStack_37;
  
  lVar2 = *param_1;
  lVar4 = param_1[1] - lVar2 >> 4;
  if (lVar4 == 0xfffffffffffffff) {
    FUN_140014450();
    pcVar3 = (code *)swi(3);
    puVar13 = (undefined1 *)(*pcVar3)();
    return puVar13;
  }
  uVar7 = param_1[2] - lVar2 >> 4;
  uVar1 = lVar4 + 1;
  if (uVar7 <= 0xfffffffffffffff - (uVar7 >> 1)) {
    uVar7 = (uVar7 >> 1) + uVar7;
    uVar11 = uVar1;
    if (uVar1 <= uVar7) {
      uVar11 = uVar7;
    }
    if (uVar11 < 0x1000000000000000) {
      puVar13 = (undefined1 *)0x0;
      _Var8 = uVar11 * 0x10;
      if (_Var8 < 0x1000) {
        if (_Var8 != 0) {
          puVar13 = (undefined1 *)operator_new(_Var8);
        }
      }
      else {
        if (_Var8 + 0x27 <= _Var8) goto LAB_140029a14;
        pvVar5 = operator_new(_Var8 + 0x27);
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
      *(ulonglong *)(puVar10 + 8) = CONCAT71(uStack_37,*param_3);
      *puVar10 = 4;
      puVar12 = (undefined1 *)param_1[1];
      puVar6 = (undefined1 *)*param_1;
      puVar9 = puVar13;
      if (param_2 == puVar12) {
        for (; puVar6 != puVar12; puVar6 = puVar6 + 0x10) {
          *puVar9 = *puVar6;
          *(undefined8 *)(puVar9 + 8) = *(undefined8 *)(puVar6 + 8);
          *puVar6 = 0;
          *(undefined8 *)(puVar6 + 8) = 0;
          puVar9 = puVar9 + 0x10;
        }
      }
      else {
        if (puVar6 != param_2) {
          do {
            *puVar9 = *puVar6;
            *(undefined8 *)(puVar9 + 8) = *(undefined8 *)(puVar6 + 8);
            *puVar6 = 0;
            *(undefined8 *)(puVar6 + 8) = 0;
            puVar6 = puVar6 + 0x10;
            puVar9 = puVar9 + 0x10;
          } while (puVar6 != param_2);
          puVar12 = (undefined1 *)param_1[1];
        }
        puVar6 = param_2;
        if (param_2 != puVar12) {
          do {
            puVar6[(longlong)(puVar10 + (0x10 - (longlong)param_2))] = *puVar6;
            *(undefined8 *)(puVar6 + (longlong)(puVar10 + (0x18 - (longlong)param_2))) =
                 *(undefined8 *)(puVar6 + 8);
            *puVar6 = 0;
            *(undefined8 *)(puVar6 + 8) = 0;
            puVar6 = puVar6 + 0x10;
          } while (puVar6 != puVar12);
        }
      }
      FUN_140029e80(param_1,(longlong)puVar13,uVar1,uVar11);
      return puVar10;
    }
  }
LAB_140029a14:
  FUN_140001670();
  pcVar3 = (code *)swi(3);
  puVar13 = (undefined1 *)(*pcVar3)();
  return puVar13;
}


// FUNCTION_END

// FUNCTION_START: FUN_140029a20 @ 140029a20