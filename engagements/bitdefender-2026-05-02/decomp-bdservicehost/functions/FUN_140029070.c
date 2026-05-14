void FUN_140029070(longlong *param_1,undefined8 *param_2,undefined8 *param_3)

{
  undefined8 *puVar1;
  code *pcVar2;
  undefined1 *puVar3;
  undefined1 *puVar4;
  longlong lVar5;
  void *pvVar6;
  undefined8 *puVar7;
  undefined8 *puVar8;
  ulonglong uVar9;
  __uint64 _Var10;
  undefined1 *puVar11;
  ulonglong uVar12;
  longlong lVar13;
  undefined1 auStack_b8 [32];
  undefined1 *local_98;
  ulonglong local_90;
  undefined1 *local_88;
  undefined8 *local_80;
  longlong *local_78;
  ulonglong local_70;
  undefined1 *local_68;
  undefined1 local_60 [8];
  undefined1 *local_58;
  undefined8 *puStack_50;
  ulonglong local_48;
  
  local_48 = DAT_14007a060 ^ (ulonglong)auStack_b8;
  lVar13 = *param_1;
  lVar5 = param_1[1] - lVar13 >> 4;
  local_80 = param_3;
  local_78 = param_1;
  if (lVar5 == 0xfffffffffffffff) {
    FUN_140014450();
    pcVar2 = (code *)swi(3);
    (*pcVar2)();
    return;
  }
  local_70 = lVar5 + 1;
  uVar9 = param_1[2] - lVar13 >> 4;
  if (uVar9 <= 0xfffffffffffffff - (uVar9 >> 1)) {
    uVar9 = (uVar9 >> 1) + uVar9;
    uVar12 = local_70;
    if (local_70 <= uVar9) {
      uVar12 = uVar9;
    }
    if (uVar12 < 0x1000000000000000) {
      _Var10 = uVar12 * 0x10;
      local_90 = uVar12;
      if (_Var10 < 0x1000) {
        if (_Var10 == 0) {
          local_88 = (undefined1 *)0x0;
        }
        else {
          local_88 = (undefined1 *)operator_new(_Var10);
          local_90 = uVar12;
        }
      }
      else {
        if (_Var10 + 0x27 <= _Var10) goto LAB_1400292c6;
        pvVar6 = operator_new(_Var10 + 0x27);
        if (pvVar6 == (void *)0x0) {
          FUN_140035d28();
          pcVar2 = (code *)swi(3);
          (*pcVar2)();
          return;
        }
        local_88 = (undefined1 *)((longlong)pvVar6 + 0x27U & 0xffffffffffffffe0);
        *(void **)(local_88 + -8) = pvVar6;
      }
      puVar4 = local_88;
      uVar9 = (longlong)param_2 - lVar13 & 0xfffffffffffffff0;
      puVar11 = local_88 + uVar9;
      local_98 = puVar11 + 0x10;
      *(undefined8 *)(puVar11 + 8) = 0;
      *puVar11 = 3;
      local_58 = (undefined1 *)0x0;
      puStack_50 = (undefined8 *)0x0;
      local_68 = local_98;
      puVar7 = (undefined8 *)operator_new(0x20);
      local_58 = local_60;
      puStack_50 = puVar7;
      FUN_14000e990(puVar7,local_80);
      *(undefined8 **)(puVar11 + 8) = puVar7;
      puVar7 = (undefined8 *)local_78[1];
      puVar8 = (undefined8 *)*local_78;
      puVar3 = puVar4;
      if (param_2 == puVar7) {
        for (; local_98 = puVar11, puVar8 != puVar7; puVar8 = puVar8 + 2) {
          *puVar3 = *(undefined1 *)puVar8;
          *(undefined8 *)(puVar3 + 8) = puVar8[1];
          *(undefined1 *)puVar8 = 0;
          puVar8[1] = 0;
          puVar3 = puVar3 + 0x10;
        }
      }
      else {
        puVar11 = puVar4;
        if (puVar8 != param_2) {
          do {
            *puVar11 = *(undefined1 *)puVar8;
            *(undefined8 *)(puVar11 + 8) = puVar8[1];
            *(undefined1 *)puVar8 = 0;
            puVar8[1] = 0;
            puVar8 = puVar8 + 2;
            puVar11 = puVar11 + 0x10;
          } while (puVar8 != param_2);
          puVar7 = (undefined8 *)local_78[1];
        }
        local_98 = puVar4;
        if (param_2 != puVar7) {
          lVar13 = uVar9 - (longlong)param_2;
          puVar8 = param_2 + 1;
          do {
            (puVar4 + lVar13 + 8)[(longlong)puVar8] = *(undefined1 *)(puVar8 + -1);
            *(undefined8 *)(puVar4 + lVar13 + 0x10 + (longlong)puVar8) = *puVar8;
            *(undefined1 *)(puVar8 + -1) = 0;
            *puVar8 = 0;
            puVar1 = puVar8 + 1;
            puVar8 = puVar8 + 2;
          } while (puVar1 != puVar7);
        }
      }
      FUN_140029e80(local_78,(longlong)puVar4,local_70,uVar12);
      FUN_14002f160(local_48 ^ (ulonglong)auStack_b8);
      return;
    }
  }
LAB_1400292c6:
  FUN_140001670();
  pcVar2 = (code *)swi(3);
  (*pcVar2)();
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_1400292e0 @ 1400292e0