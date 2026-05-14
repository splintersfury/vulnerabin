uint * FUN_1400054f0(uint *param_1,uint *param_2,longlong param_3)

{
  ulonglong *puVar1;
  uint *puVar2;
  ushort uVar3;
  ushort uVar4;
  short sVar5;
  ulonglong uVar6;
  longlong lVar7;
  code *pcVar8;
  bool bVar9;
  uint *puVar10;
  uint *puVar11;
  uint *puVar12;
  uint *puVar13;
  ulonglong uVar14;
  uint *puVar15;
  uint *puVar16;
  uint *puVar17;
  ulonglong uVar18;
  bool bVar19;
  
  bVar9 = FUN_140005730(param_2);
  if (bVar9) {
    if (param_1 == param_2) {
      return param_1;
    }
    puVar1 = (ulonglong *)(param_2 + 4);
    if (7 < *(ulonglong *)(param_2 + 6)) {
      param_2 = *(uint **)param_2;
    }
    FUN_140010340((longlong *)param_1,(undefined8 *)param_2,*puVar1);
    return param_1;
  }
  uVar18 = *(ulonglong *)(param_1 + 6);
  puVar12 = param_1;
  if (7 < uVar18) {
    puVar12 = *(uint **)param_1;
  }
  uVar6 = *(ulonglong *)(param_1 + 4);
  puVar17 = param_2;
  if (7 < *(ulonglong *)(param_2 + 6)) {
    puVar17 = *(uint **)param_2;
  }
  uVar14 = *(ulonglong *)(param_2 + 4);
  puVar2 = (uint *)((longlong)puVar17 + uVar14 * 2);
  puVar10 = FUN_140005400(puVar12,(uint *)((longlong)puVar12 + uVar6 * 2));
  puVar13 = puVar2;
  puVar11 = FUN_140005400(puVar17,puVar2);
  if (puVar17 != puVar11) {
    puVar15 = (uint *)((longlong)puVar11 - (longlong)puVar17 >> 1);
    puVar16 = (uint *)((longlong)puVar10 - (longlong)puVar12 >> 1);
    puVar13 = puVar16;
    if (puVar15 < puVar16) {
      puVar13 = puVar15;
    }
    if (puVar13 != (uint *)0x0) {
      uVar4 = (ushort)*puVar12;
      uVar3 = (ushort)*puVar17;
      if (uVar3 <= uVar4) {
        param_3 = (longlong)puVar12 - (longlong)puVar17;
        bVar9 = uVar4 < uVar3;
        bVar19 = uVar4 == uVar3;
        do {
          if (!bVar9 && !bVar19) break;
          if (puVar13 == (uint *)0x1) goto LAB_1400055eb;
          uVar4 = *(ushort *)((longlong)puVar17 + param_3 + 2);
          puVar17 = (uint *)((longlong)puVar17 + 2);
          puVar13 = (uint *)((longlong)puVar13 + -1);
          bVar9 = uVar4 < *(ushort *)puVar17;
          bVar19 = uVar4 == *(ushort *)puVar17;
        } while (!bVar9);
      }
LAB_1400055f2:
      if (param_1 == param_2) {
        return param_1;
      }
      if (7 < *(ulonglong *)(param_2 + 6)) {
        param_2 = *(uint **)param_2;
      }
      FUN_140010340((longlong *)param_1,(undefined8 *)param_2,uVar14);
      return param_1;
    }
LAB_1400055eb:
    if ((puVar16 < puVar15) || (puVar15 < puVar16)) goto LAB_1400055f2;
  }
  if ((puVar11 == puVar2) || (((short)*puVar11 != 0x5c && ((short)*puVar11 != 0x2f)))) {
    puVar17 = (uint *)((longlong)puVar12 + uVar6 * 2);
    if (puVar10 == puVar17) {
      if ((longlong)((longlong)puVar10 - (longlong)puVar12 & 0xfffffffffffffffeU) < 6)
      goto LAB_1400056af;
    }
    else {
      sVar5 = *(short *)((longlong)puVar17 + -2);
      if ((sVar5 == 0x5c) || (sVar5 == 0x2f)) goto LAB_1400056af;
    }
    if (uVar6 < uVar18) {
      *(ulonglong *)(param_1 + 4) = uVar6 + 1;
      puVar12 = param_1;
      if (7 < uVar18) {
        puVar12 = *(uint **)param_1;
      }
      *(undefined4 *)((longlong)puVar12 + uVar6 * 2) = 0x5c;
    }
    else {
      FUN_140013030((undefined8 *)param_1,puVar13,param_3,0x5c);
    }
  }
  else {
    uVar14 = (longlong)puVar10 - (longlong)puVar12 >> 1;
    if (uVar6 < uVar14) {
      FUN_140011df0();
      pcVar8 = (code *)swi(3);
      puVar12 = (uint *)(*pcVar8)();
      return puVar12;
    }
    puVar12 = param_1;
    if (7 < uVar18) {
      puVar12 = *(uint **)param_1;
    }
    *(ulonglong *)(param_1 + 4) = uVar14;
    *(undefined2 *)((longlong)puVar12 + uVar14 * 2) = 0;
  }
LAB_1400056af:
  lVar7 = *(longlong *)(param_1 + 4);
  uVar18 = (longlong)puVar2 - (longlong)puVar11 >> 1;
  if (*(ulonglong *)(param_1 + 6) - lVar7 < uVar18) {
    FUN_1400131d0((undefined8 *)param_1,uVar18,param_3,(undefined8 *)puVar11,uVar18);
  }
  else {
    *(ulonglong *)(param_1 + 4) = lVar7 + uVar18;
    puVar12 = param_1;
    if (7 < *(ulonglong *)(param_1 + 6)) {
      puVar12 = *(uint **)param_1;
    }
    FUN_1400316b0((undefined8 *)((longlong)puVar12 + lVar7 * 2),(undefined8 *)puVar11,uVar18 * 2);
    *(undefined2 *)((longlong)puVar12 + (lVar7 + uVar18) * 2) = 0;
  }
  return param_1;
}


// FUNCTION_END

// FUNCTION_START: FUN_140005730 @ 140005730