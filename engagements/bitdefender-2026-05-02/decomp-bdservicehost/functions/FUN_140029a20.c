char * FUN_140029a20(longlong *param_1,undefined1 *param_2)

{
  ulonglong uVar1;
  longlong lVar2;
  code *pcVar3;
  longlong lVar4;
  void *pvVar5;
  undefined1 *puVar6;
  char *pcVar7;
  ulonglong uVar8;
  __uint64 _Var9;
  undefined1 *puVar10;
  ulonglong uVar11;
  undefined1 *puVar12;
  undefined1 *puVar13;
  
  lVar2 = *param_1;
  lVar4 = param_1[1] - lVar2 >> 4;
  if (lVar4 == 0xfffffffffffffff) {
    FUN_140014450();
    pcVar3 = (code *)swi(3);
    pcVar7 = (char *)(*pcVar3)();
    return pcVar7;
  }
  uVar1 = lVar4 + 1;
  uVar8 = param_1[2] - lVar2 >> 4;
  if (uVar8 <= 0xfffffffffffffff - (uVar8 >> 1)) {
    uVar8 = (uVar8 >> 1) + uVar8;
    uVar11 = uVar1;
    if (uVar1 <= uVar8) {
      uVar11 = uVar8;
    }
    if (uVar11 < 0x1000000000000000) {
      _Var9 = uVar11 * 0x10;
      puVar12 = (undefined1 *)0x0;
      if (_Var9 < 0x1000) {
        if (_Var9 != 0) {
          puVar12 = (undefined1 *)operator_new(_Var9);
        }
      }
      else {
        if (_Var9 + 0x27 <= _Var9) goto LAB_140029bcf;
        pvVar5 = operator_new(_Var9 + 0x27);
        if (pvVar5 == (void *)0x0) {
          FUN_140035d28();
          pcVar3 = (code *)swi(3);
          pcVar7 = (char *)(*pcVar3)();
          return pcVar7;
        }
        puVar12 = (undefined1 *)((longlong)pvVar5 + 0x27U & 0xffffffffffffffe0);
        *(void **)(puVar12 + -8) = pvVar5;
      }
      pcVar7 = puVar12 + ((longlong)param_2 - lVar2 & 0xfffffffffffffff0);
      FUN_14001de50(pcVar7,'\0');
      puVar13 = (undefined1 *)param_1[1];
      puVar6 = (undefined1 *)*param_1;
      puVar10 = puVar12;
      if (param_2 == puVar13) {
        for (; puVar6 != puVar13; puVar6 = puVar6 + 0x10) {
          *puVar10 = *puVar6;
          *(undefined8 *)(puVar10 + 8) = *(undefined8 *)(puVar6 + 8);
          *puVar6 = 0;
          *(undefined8 *)(puVar6 + 8) = 0;
          puVar10 = puVar10 + 0x10;
        }
      }
      else {
        if (puVar6 != param_2) {
          do {
            *puVar10 = *puVar6;
            *(undefined8 *)(puVar10 + 8) = *(undefined8 *)(puVar6 + 8);
            *puVar6 = 0;
            *(undefined8 *)(puVar6 + 8) = 0;
            puVar6 = puVar6 + 0x10;
            puVar10 = puVar10 + 0x10;
          } while (puVar6 != param_2);
          puVar13 = (undefined1 *)param_1[1];
        }
        puVar6 = param_2;
        if (param_2 != puVar13) {
          do {
            puVar6[(longlong)(pcVar7 + (0x10 - (longlong)param_2))] = *puVar6;
            *(undefined8 *)(puVar6 + (longlong)(pcVar7 + (0x18 - (longlong)param_2))) =
                 *(undefined8 *)(puVar6 + 8);
            *puVar6 = 0;
            *(undefined8 *)(puVar6 + 8) = 0;
            puVar6 = puVar6 + 0x10;
          } while (puVar6 != puVar13);
        }
      }
      FUN_140029e80(param_1,(longlong)puVar12,uVar1,uVar11);
      return pcVar7;
    }
  }
LAB_140029bcf:
  FUN_140001670();
  pcVar3 = (code *)swi(3);
  pcVar7 = (char *)(*pcVar3)();
  return pcVar7;
}


// FUNCTION_END

// FUNCTION_START: FUN_140029be0 @ 140029be0