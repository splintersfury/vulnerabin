char * FUN_140028e40(longlong *param_1,undefined8 *param_2,char *param_3)

{
  ulonglong uVar1;
  undefined8 *puVar2;
  longlong lVar3;
  code *pcVar4;
  longlong lVar5;
  void *pvVar6;
  undefined8 *puVar7;
  ulonglong uVar8;
  __uint64 _Var9;
  undefined1 *puVar10;
  undefined1 *puVar11;
  undefined8 *puVar12;
  ulonglong uVar13;
  char *pcVar14;
  
  lVar3 = *param_1;
  lVar5 = param_1[1] - lVar3 >> 4;
  if (lVar5 == 0xfffffffffffffff) {
    FUN_140014450();
    pcVar4 = (code *)swi(3);
    pcVar14 = (char *)(*pcVar4)();
    return pcVar14;
  }
  uVar1 = lVar5 + 1;
  uVar8 = param_1[2] - lVar3 >> 4;
  if (uVar8 <= 0xfffffffffffffff - (uVar8 >> 1)) {
    uVar8 = (uVar8 >> 1) + uVar8;
    uVar13 = uVar1;
    if (uVar1 <= uVar8) {
      uVar13 = uVar8;
    }
    if (uVar13 < 0x1000000000000000) {
      _Var9 = uVar13 * 0x10;
      if (_Var9 < 0x1000) {
        if (_Var9 == 0) {
          puVar11 = (undefined1 *)0x0;
        }
        else {
          puVar11 = (undefined1 *)operator_new(_Var9);
        }
      }
      else {
        if (_Var9 + 0x27 <= _Var9) goto LAB_140029050;
        pvVar6 = operator_new(_Var9 + 0x27);
        if (pvVar6 == (void *)0x0) {
          FUN_140035d28();
          pcVar4 = (code *)swi(3);
          pcVar14 = (char *)(*pcVar4)();
          return pcVar14;
        }
        puVar11 = (undefined1 *)((longlong)pvVar6 + 0x27U & 0xffffffffffffffe0);
        *(void **)(puVar11 + -8) = pvVar6;
      }
      pcVar14 = puVar11 + ((longlong)param_2 - lVar3 & 0xfffffffffffffff0);
      FUN_14001de50(pcVar14,*param_3);
      puVar12 = (undefined8 *)param_1[1];
      puVar7 = (undefined8 *)*param_1;
      puVar10 = puVar11;
      if (param_2 == puVar12) {
        for (; puVar7 != puVar12; puVar7 = puVar7 + 2) {
          *puVar10 = *(undefined1 *)puVar7;
          *(undefined8 *)(puVar10 + 8) = puVar7[1];
          *(undefined1 *)puVar7 = 0;
          puVar7[1] = 0;
          puVar10 = puVar10 + 0x10;
        }
      }
      else {
        if (puVar7 != param_2) {
          do {
            *puVar10 = *(undefined1 *)puVar7;
            *(undefined8 *)(puVar10 + 8) = puVar7[1];
            *(undefined1 *)puVar7 = 0;
            puVar7[1] = 0;
            puVar7 = puVar7 + 2;
            puVar10 = puVar10 + 0x10;
          } while (puVar7 != param_2);
          puVar12 = (undefined8 *)param_1[1];
        }
        if (param_2 != puVar12) {
          puVar7 = param_2 + 1;
          do {
            (pcVar14 + (8 - (longlong)param_2))[(longlong)puVar7] = *(char *)(puVar7 + -1);
            *(undefined8 *)(pcVar14 + (0x10 - (longlong)param_2) + (longlong)puVar7) = *puVar7;
            *(undefined1 *)(puVar7 + -1) = 0;
            *puVar7 = 0;
            puVar2 = puVar7 + 1;
            puVar7 = puVar7 + 2;
          } while (puVar2 != puVar12);
        }
      }
      FUN_140029e80(param_1,(longlong)puVar11,uVar1,uVar13);
      return pcVar14;
    }
  }
LAB_140029050:
  FUN_140001670();
  pcVar4 = (code *)swi(3);
  pcVar14 = (char *)(*pcVar4)();
  return pcVar14;
}


// FUNCTION_END

// FUNCTION_START: FUN_140029070 @ 140029070