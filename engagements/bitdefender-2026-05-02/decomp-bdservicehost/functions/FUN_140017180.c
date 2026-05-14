longlong * FUN_140017180(float *param_1,longlong *param_2,byte *param_3)

{
  float *pfVar1;
  int iVar2;
  ulonglong uVar3;
  longlong *plVar4;
  undefined8 *puVar5;
  code *pcVar6;
  longlong *plVar7;
  longlong lVar8;
  ulonglong uVar9;
  ulonglong uVar10;
  ulonglong uVar11;
  float fVar12;
  longlong *local_48;
  
  uVar11 = (((((ulonglong)*param_3 ^ 0xcbf29ce484222325) * 0x100000001b3 ^ (ulonglong)param_3[1]) *
             0x100000001b3 ^ (ulonglong)param_3[2]) * 0x100000001b3 ^ (ulonglong)param_3[3]) *
           0x100000001b3;
  plVar7 = *(longlong **)
            (*(longlong *)(param_1 + 6) + 8 + (uVar11 & *(ulonglong *)(param_1 + 0xc)) * 0x10);
  pfVar1 = param_1 + 2;
  local_48 = *(longlong **)pfVar1;
  if (plVar7 != local_48) {
    iVar2 = (int)plVar7[2];
    local_48 = plVar7;
    while( true ) {
      if (*(int *)param_3 == iVar2) {
        *param_2 = (longlong)local_48;
        *(undefined1 *)(param_2 + 1) = 0;
        return param_2;
      }
      if (local_48 ==
          *(longlong **)
           (*(longlong *)(param_1 + 6) + (uVar11 & *(ulonglong *)(param_1 + 0xc)) * 0x10)) break;
      local_48 = (longlong *)local_48[1];
      iVar2 = (int)local_48[2];
    }
  }
  if (*(longlong *)(param_1 + 4) == 0x7ffffffffffffff) {
    FUN_14002d6f4(0x14006bd58);
    pcVar6 = (code *)swi(3);
    plVar7 = (longlong *)(*pcVar6)();
    return plVar7;
  }
  plVar7 = (longlong *)operator_new(0x20);
  lVar8 = *(longlong *)(param_3 + 8);
  plVar7[2] = *(longlong *)param_3;
  plVar7[3] = lVar8;
  lVar8 = *(longlong *)(param_1 + 4);
  uVar3 = *(ulonglong *)(param_1 + 0xe);
  if (*param_1 < (float)(lVar8 + 1) / (float)uVar3) {
    fVar12 = ceilf((float)(lVar8 + 1) / *param_1);
    lVar8 = 0;
    if ((DAT_14006e170 <= fVar12) && (fVar12 = fVar12 - DAT_14006e170, fVar12 < DAT_14006e170)) {
      lVar8 = -0x8000000000000000;
    }
    uVar9 = 8;
    if (8 < (ulonglong)((longlong)fVar12 + lVar8)) {
      uVar9 = (longlong)fVar12 + lVar8;
    }
    uVar10 = uVar3;
    if ((uVar3 < uVar9) && ((0x1ff < uVar3 || (uVar10 = uVar3 * 8, uVar3 * 8 < uVar9)))) {
      uVar10 = uVar9;
    }
    FUN_140017450((longlong)param_1,uVar10);
    plVar4 = *(longlong **)
              (*(longlong *)(param_1 + 6) + 8 + (uVar11 & *(ulonglong *)(param_1 + 0xc)) * 0x10);
    local_48 = *(longlong **)pfVar1;
    if (plVar4 != local_48) {
      iVar2 = (int)plVar4[2];
      local_48 = plVar4;
      while ((int)plVar7[2] != iVar2) {
        if (local_48 ==
            *(longlong **)
             (*(longlong *)(param_1 + 6) + (uVar11 & *(ulonglong *)(param_1 + 0xc)) * 0x10))
        goto LAB_14001739c;
        local_48 = (longlong *)local_48[1];
        iVar2 = (int)local_48[2];
      }
      local_48 = (longlong *)*local_48;
    }
LAB_14001739c:
    lVar8 = *(longlong *)(param_1 + 4);
  }
  puVar5 = (undefined8 *)local_48[1];
  *(longlong *)(param_1 + 4) = lVar8 + 1;
  *plVar7 = (longlong)local_48;
  plVar7[1] = (longlong)puVar5;
  *puVar5 = plVar7;
  local_48[1] = (longlong)plVar7;
  lVar8 = *(longlong *)(param_1 + 6);
  uVar11 = uVar11 & *(ulonglong *)(param_1 + 0xc);
  plVar4 = *(longlong **)(lVar8 + uVar11 * 0x10);
  if (plVar4 == *(longlong **)pfVar1) {
    *(longlong **)(lVar8 + uVar11 * 0x10) = plVar7;
  }
  else {
    if (plVar4 == local_48) {
      *(longlong **)(lVar8 + uVar11 * 0x10) = plVar7;
      goto LAB_14001740c;
    }
    if (*(undefined8 **)(lVar8 + 8 + uVar11 * 0x10) != puVar5) goto LAB_14001740c;
  }
  *(longlong **)(lVar8 + 8 + uVar11 * 0x10) = plVar7;
LAB_14001740c:
  *param_2 = (longlong)plVar7;
  *(undefined1 *)(param_2 + 1) = 1;
  return param_2;
}


// FUNCTION_END

// FUNCTION_START: FUN_140017450 @ 140017450