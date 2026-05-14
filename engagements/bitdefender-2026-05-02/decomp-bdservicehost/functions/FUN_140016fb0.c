void FUN_140016fb0(ulonglong *param_1,ulonglong param_2,undefined8 param_3)

{
  ulonglong uVar1;
  undefined8 *puVar2;
  code *pcVar3;
  void *pvVar4;
  ulonglong uVar5;
  undefined8 *puVar6;
  
  puVar6 = (undefined8 *)*param_1;
  puVar2 = (undefined8 *)param_1[1];
  uVar5 = (longlong)puVar2 - (longlong)puVar6 >> 3;
  if (uVar5 < param_2) {
    if (0x1fffffffffffffff < param_2) {
LAB_1400170e2:
      FUN_140001670();
      pcVar3 = (code *)swi(3);
      (*pcVar3)();
      return;
    }
    uVar1 = param_2 * 8;
    if (uVar1 < 0x1000) {
      if (uVar1 == 0) {
        puVar6 = (undefined8 *)0x0;
      }
      else {
        puVar6 = (undefined8 *)operator_new(uVar1);
      }
    }
    else {
      if (uVar1 + 0x27 <= uVar1) goto LAB_1400170e2;
      pvVar4 = operator_new(uVar1 + 0x27);
      if (pvVar4 == (void *)0x0) goto LAB_1400170e8;
      puVar6 = (undefined8 *)((longlong)pvVar4 + 0x27U & 0xffffffffffffffe0);
      puVar6[-1] = pvVar4;
    }
    if (uVar5 != 0) {
      if ((0xfff < uVar5 * 8) && (0x1f < (*param_1 - *(longlong *)(*param_1 - 8)) - 8)) {
LAB_1400170e8:
        FUN_140035d28();
        pcVar3 = (code *)swi(3);
        (*pcVar3)();
        return;
      }
      FUN_14002f180();
    }
    puVar2 = puVar6 + param_2;
    *param_1 = (ulonglong)puVar6;
    param_1[1] = (ulonglong)puVar2;
    param_1[2] = (ulonglong)puVar2;
    for (; puVar6 != puVar2; puVar6 = puVar6 + 1) {
      *puVar6 = param_3;
    }
  }
  else {
    uVar5 = (ulonglong)((longlong)puVar2 + (7 - (longlong)puVar6)) >> 3;
    if (puVar2 < puVar6) {
      uVar5 = 0;
    }
    if (uVar5 != 0) {
      for (; uVar5 != 0; uVar5 = uVar5 - 1) {
        *puVar6 = param_3;
        puVar6 = puVar6 + 1;
      }
      return;
    }
  }
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_1400170f0 @ 1400170f0