longlong * FUN_140025f10(longlong *param_1,longlong *param_2,longlong *param_3)

{
  longlong lVar1;
  uint *puVar2;
  code *pcVar3;
  uint uVar4;
  longlong *plVar5;
  ulonglong uVar6;
  ulonglong uVar7;
  longlong lVar8;
  uint *puVar9;
  uint *puVar10;
  longlong lVar11;
  ulonglong uStack_20;
  
  puVar2 = (uint *)*param_1;
  uStack_20 = 0;
  uVar7 = param_1[3];
  puVar10 = puVar2;
  if (uVar7 != 0) {
    uVar6 = (*param_3 - (longlong)puVar2 >> 2) * 0x20 + param_3[1];
    if (((longlong)uVar6 < 0) && (uVar6 != 0)) {
      lVar11 = -((~uVar6 >> 5) * 4 + 4);
    }
    else {
      lVar11 = (uVar6 >> 5) * 4;
    }
    puVar10 = (uint *)((longlong)puVar2 + lVar11);
    uStack_20 = (ulonglong)((uint)uVar6 & 0x1f);
  }
  uVar6 = uStack_20;
  lVar11 = ((longlong)puVar10 - (longlong)puVar2 >> 2) * 0x20 + uStack_20;
  if (((longlong)uVar7 < 0) && (uVar7 != 0)) {
    lVar8 = -((~uVar7 >> 5) * 4 + 4);
  }
  else {
    lVar8 = (uVar7 >> 5) * 4;
  }
  if (uStack_20 < 0x1f) {
    uStack_20 = uStack_20 + 1;
    puVar9 = puVar10;
  }
  else {
    uStack_20 = 0;
    puVar9 = puVar10 + 1;
  }
  while ((puVar9 != (uint *)((longlong)puVar2 + lVar8) || (uStack_20 != ((uint)uVar7 & 0x1f)))) {
    if ((*puVar9 & 1 << ((byte)uStack_20 & 0x1f)) == 0) {
      uVar4 = *puVar10 & ~(1 << ((uint)uVar6 & 0x1f));
    }
    else {
      uVar4 = *puVar10 | 1 << ((uint)uVar6 & 0x1f);
    }
    *puVar10 = uVar4;
    if (uVar6 < 0x1f) {
      uVar6 = uVar6 + 1;
    }
    else {
      uVar6 = 0;
      puVar10 = puVar10 + 1;
    }
    if (uStack_20 < 0x1f) {
      uStack_20 = uStack_20 + 1;
    }
    else {
      uStack_20 = 0;
      puVar9 = puVar9 + 1;
    }
  }
  uVar7 = param_1[3] - 1;
  if (0x7fffffffffffffff < uVar7) {
    FUN_140021870();
    pcVar3 = (code *)swi(3);
    plVar5 = (longlong *)(*pcVar3)();
    return plVar5;
  }
  uVar6 = param_1[3] + 0x1eU >> 5;
  lVar8 = *param_1;
  if ((uVar6 < (ulonglong)(param_1[1] - lVar8 >> 2)) &&
     (lVar1 = lVar8 + uVar6 * 4, lVar1 != param_1[1])) {
    param_1[1] = lVar1;
  }
  param_1[3] = uVar7;
  if ((uVar7 & 0x1f) != 0) {
    puVar2 = (uint *)(lVar8 + -4 + uVar6 * 4);
    *puVar2 = *puVar2 & (1 << ((byte)uVar7 & 0x1f)) - 1U;
    lVar8 = *param_1;
  }
  *param_2 = lVar8;
  param_2[1] = 0;
  if ((lVar11 < 0) && ((ulonglong)param_2[1] < (ulonglong)-lVar11)) {
    uVar7 = param_2[1] + lVar11;
    *param_2 = *param_2 + (~uVar7 >> 5) * -4 + -4;
  }
  else {
    uVar7 = param_2[1] + lVar11;
    *param_2 = *param_2 + (uVar7 >> 5) * 4;
  }
  param_2[1] = (ulonglong)((uint)uVar7 & 0x1f);
  return param_2;
}


// FUNCTION_END

// FUNCTION_START: FUN_140026150 @ 140026150