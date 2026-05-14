void FUN_1400267d0(longlong *param_1,ulonglong param_2,int *param_3)

{
  undefined1 (*pauVar1) [16];
  code *pcVar2;
  ulonglong uVar3;
  void *pvVar4;
  ulonglong uVar5;
  undefined8 *puVar6;
  longlong lVar7;
  
  if (0x3fffffffffffffff < param_2) {
    FUN_140014450();
    pcVar2 = (code *)swi(3);
    (*pcVar2)();
    return;
  }
  uVar5 = param_1[2] - *param_1 >> 2;
  lVar7 = param_1[1] - *param_1 >> 2;
  if ((0x3fffffffffffffff - (uVar5 >> 1) < uVar5) ||
     ((uVar5 = (uVar5 >> 1) + uVar5, uVar3 = param_2, param_2 <= uVar5 &&
      (uVar3 = uVar5, 0x3fffffffffffffff < uVar5)))) {
LAB_14002694b:
    FUN_140001670();
    pcVar2 = (code *)swi(3);
    (*pcVar2)();
    return;
  }
  uVar3 = uVar3 * 4;
  if (uVar3 < 0x1000) {
    if (uVar3 == 0) {
      puVar6 = (undefined8 *)0x0;
    }
    else {
      puVar6 = (undefined8 *)operator_new(uVar3);
    }
  }
  else {
    if (uVar3 + 0x27 <= uVar3) goto LAB_14002694b;
    pvVar4 = operator_new(uVar3 + 0x27);
    if (pvVar4 == (void *)0x0) goto LAB_140026945;
    puVar6 = (undefined8 *)((longlong)pvVar4 + 0x27U & 0xffffffffffffffe0);
    puVar6[-1] = pvVar4;
  }
  pauVar1 = (undefined1 (*) [16])((longlong)puVar6 + lVar7 * 4);
  lVar7 = param_2 - lVar7;
  if (*param_3 == 0) {
    FUN_140031e00(pauVar1,0,lVar7 * 4);
  }
  else {
    for (; lVar7 != 0; lVar7 = lVar7 + -1) {
      *(int *)*pauVar1 = *param_3;
      pauVar1 = (undefined1 (*) [16])(*pauVar1 + 4);
    }
  }
  FUN_1400316b0(puVar6,(undefined8 *)*param_1,param_1[1] - *param_1);
  lVar7 = *param_1;
  if (lVar7 != 0) {
    if ((0xfff < (param_1[2] - lVar7 & 0xfffffffffffffffcU)) &&
       (0x1f < (lVar7 - *(longlong *)(lVar7 + -8)) - 8U)) {
LAB_140026945:
      FUN_140035d28();
      pcVar2 = (code *)swi(3);
      (*pcVar2)();
      return;
    }
    FUN_14002f180();
  }
  *param_1 = (longlong)puVar6;
  param_1[1] = (longlong)puVar6 + param_2 * 4;
  param_1[2] = uVar3 + (longlong)puVar6;
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_140026960 @ 140026960