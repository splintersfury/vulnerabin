longlong * FUN_140026490(float *param_1,longlong *param_2,longlong *param_3)

{
  ulonglong uVar1;
  size_t _Size;
  undefined8 *puVar2;
  code *pcVar3;
  int iVar4;
  longlong *plVar5;
  ulonglong uVar6;
  longlong *plVar7;
  longlong lVar8;
  ulonglong uVar9;
  longlong *_Buf1;
  longlong *plVar10;
  longlong *plVar11;
  ulonglong uVar12;
  float fVar13;
  longlong *local_58;
  
  uVar1 = param_3[2];
  uVar9 = param_3[3];
  plVar5 = param_3;
  if (0xf < uVar9) {
    plVar5 = (longlong *)*param_3;
  }
  uVar6 = 0;
  uVar12 = 0xcbf29ce484222325;
  if (uVar1 != 0) {
    do {
      uVar12 = (uVar12 ^ *(byte *)(uVar6 + (longlong)plVar5)) * 0x100000001b3;
      uVar6 = uVar6 + 1;
    } while (uVar6 < uVar1);
  }
  plVar5 = *(longlong **)
            (*(longlong *)(param_1 + 6) + 8 + (*(ulonglong *)(param_1 + 0xc) & uVar12) * 0x10);
  local_58 = *(longlong **)(param_1 + 2);
  if (plVar5 != *(longlong **)(param_1 + 2)) {
    plVar11 = *(longlong **)
               (*(longlong *)(param_1 + 6) + (*(ulonglong *)(param_1 + 0xc) & uVar12) * 0x10);
    while( true ) {
      plVar10 = plVar5 + 2;
      if (0xf < (ulonglong)plVar5[5]) {
        plVar10 = (longlong *)*plVar10;
      }
      plVar7 = param_3;
      if (0xf < uVar9) {
        plVar7 = (longlong *)*param_3;
      }
      if ((uVar1 == plVar5[4]) && (iVar4 = memcmp(plVar7,plVar10,uVar1), iVar4 == 0)) {
        *param_2 = (longlong)plVar5;
        *(undefined1 *)(param_2 + 1) = 0;
        return param_2;
      }
      local_58 = plVar5;
      if (plVar5 == plVar11) break;
      plVar5 = (longlong *)plVar5[1];
    }
  }
  if (*(longlong *)(param_1 + 4) == 0x492492492492492) {
    FUN_14002d6f4(0x14006bd58);
    pcVar3 = (code *)swi(3);
    plVar5 = (longlong *)(*pcVar3)();
    return plVar5;
  }
  plVar5 = (longlong *)operator_new(0x38);
  FUN_14000e990(plVar5 + 2,param_3);
  *(int *)(plVar5 + 6) = (int)param_3[4];
  lVar8 = *(longlong *)(param_1 + 4);
  uVar1 = *(ulonglong *)(param_1 + 0xe);
  if (*param_1 < (float)(lVar8 + 1) / (float)uVar1) {
    fVar13 = ceilf((float)(lVar8 + 1) / *param_1);
    lVar8 = 0;
    if ((DAT_14006e170 <= fVar13) && (fVar13 = fVar13 - DAT_14006e170, fVar13 < DAT_14006e170)) {
      lVar8 = -0x8000000000000000;
    }
    uVar9 = 8;
    if (8 < (ulonglong)((longlong)fVar13 + lVar8)) {
      uVar9 = (longlong)fVar13 + lVar8;
    }
    uVar6 = uVar1;
    if ((uVar1 < uVar9) && ((0x1ff < uVar1 || (uVar6 = uVar1 * 8, uVar1 * 8 < uVar9)))) {
      uVar6 = uVar9;
    }
    FUN_140028bc0((longlong)param_1,uVar6);
    plVar11 = *(longlong **)
               (*(longlong *)(param_1 + 6) + 8 + (*(ulonglong *)(param_1 + 0xc) & uVar12) * 0x10);
    local_58 = *(longlong **)(param_1 + 2);
    if (plVar11 != local_58) {
      plVar10 = *(longlong **)
                 (*(longlong *)(param_1 + 6) + (*(ulonglong *)(param_1 + 0xc) & uVar12) * 0x10);
      uVar1 = plVar5[5];
      _Size = plVar5[4];
      while( true ) {
        plVar7 = plVar11 + 2;
        if (0xf < (ulonglong)plVar11[5]) {
          plVar7 = (longlong *)*plVar7;
        }
        _Buf1 = plVar5 + 2;
        if (0xf < uVar1) {
          _Buf1 = (longlong *)plVar5[2];
        }
        if ((_Size == plVar11[4]) && (iVar4 = memcmp(_Buf1,plVar7,_Size), iVar4 == 0)) break;
        local_58 = plVar11;
        if (plVar11 == plVar10) goto LAB_140026733;
        plVar11 = (longlong *)plVar11[1];
      }
      local_58 = (longlong *)*plVar11;
    }
LAB_140026733:
    lVar8 = *(longlong *)(param_1 + 4);
  }
  puVar2 = (undefined8 *)local_58[1];
  *(longlong *)(param_1 + 4) = lVar8 + 1;
  *plVar5 = (longlong)local_58;
  plVar5[1] = (longlong)puVar2;
  *puVar2 = plVar5;
  local_58[1] = (longlong)plVar5;
  lVar8 = *(longlong *)(param_1 + 6);
  uVar12 = *(ulonglong *)(param_1 + 0xc) & uVar12;
  plVar11 = *(longlong **)(lVar8 + uVar12 * 0x10);
  if (plVar11 == *(longlong **)(param_1 + 2)) {
    *(longlong **)(lVar8 + uVar12 * 0x10) = plVar5;
  }
  else {
    if (plVar11 == local_58) {
      *(longlong **)(lVar8 + uVar12 * 0x10) = plVar5;
      goto LAB_14002679b;
    }
    if (*(undefined8 **)(lVar8 + 8 + uVar12 * 0x10) != puVar2) goto LAB_14002679b;
  }
  *(longlong **)(lVar8 + 8 + uVar12 * 0x10) = plVar5;
LAB_14002679b:
  *param_2 = (longlong)plVar5;
  *(undefined1 *)(param_2 + 1) = 1;
  return param_2;
}


// FUNCTION_END

// FUNCTION_START: FUN_1400267d0 @ 1400267d0