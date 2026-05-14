void FUN_140028bc0(longlong param_1,ulonglong param_2)

{
  byte *pbVar1;
  longlong *plVar2;
  longlong *plVar3;
  ulonglong _Size;
  longlong *plVar4;
  undefined8 *puVar5;
  undefined8 *puVar6;
  code *pcVar7;
  longlong *plVar8;
  int iVar9;
  ulonglong uVar10;
  ulonglong uVar11;
  longlong *plVar12;
  ulonglong uVar13;
  longlong *plVar14;
  longlong lVar15;
  longlong *plVar16;
  undefined8 *puVar17;
  
  for (lVar15 = 0x3f; 0xfffffffffffffffU >> lVar15 == 0; lVar15 = lVar15 + -1) {
  }
  if ((ulonglong)(1L << ((byte)lVar15 & 0x3f)) < param_2) {
    FUN_14002d6f4(0x14006bd78);
    pcVar7 = (code *)swi(3);
    (*pcVar7)();
    return;
  }
  plVar2 = *(longlong **)(param_1 + 8);
  uVar10 = param_2 - 1 | 1;
  lVar15 = 0x3f;
  if (uVar10 != 0) {
    for (; uVar10 >> lVar15 == 0; lVar15 = lVar15 + -1) {
    }
  }
  lVar15 = 1L << ((char)lVar15 + 1U & 0x3f);
  FUN_140016fb0((ulonglong *)(param_1 + 0x18),lVar15 * 2,plVar2);
  *(longlong *)(param_1 + 0x38) = lVar15;
  *(longlong *)(param_1 + 0x30) = lVar15 + -1;
  plVar8 = (longlong *)**(undefined8 **)(param_1 + 8);
joined_r0x000140028c43:
  do {
    while( true ) {
      if (plVar8 == plVar2) {
        return;
      }
      uVar10 = plVar8[5];
      plVar16 = plVar8 + 2;
      plVar3 = (longlong *)*plVar8;
      _Size = plVar8[4];
      if (0xf < uVar10) {
        plVar16 = (longlong *)plVar8[2];
      }
      uVar11 = 0;
      uVar13 = 0xcbf29ce484222325;
      if (_Size != 0) {
        do {
          pbVar1 = (byte *)(uVar11 + (longlong)plVar16);
          uVar11 = uVar11 + 1;
          uVar13 = (uVar13 ^ *pbVar1) * 0x100000001b3;
        } while (uVar11 < _Size);
      }
      puVar17 = (undefined8 *)
                ((*(ulonglong *)(param_1 + 0x30) & uVar13) * 0x10 + *(longlong *)(param_1 + 0x18));
      plVar16 = (longlong *)*puVar17;
      if (plVar16 != plVar2) break;
      *puVar17 = plVar8;
      puVar17[1] = plVar8;
      plVar8 = plVar3;
    }
    plVar4 = (longlong *)puVar17[1];
    plVar14 = plVar4 + 2;
    if (0xf < (ulonglong)plVar4[5]) {
      plVar14 = (longlong *)*plVar14;
    }
    plVar12 = plVar8 + 2;
    if (0xf < uVar10) {
      plVar12 = (longlong *)plVar8[2];
    }
    if (_Size != plVar4[4]) {
joined_r0x000140028d44:
      while (plVar16 != plVar4) {
        plVar4 = (longlong *)plVar4[1];
        plVar14 = plVar4 + 2;
        if (0xf < (ulonglong)plVar4[5]) {
          plVar14 = (longlong *)*plVar14;
        }
        plVar12 = plVar8 + 2;
        if (0xf < uVar10) {
          plVar12 = (longlong *)plVar8[2];
        }
        if (_Size == plVar4[4]) {
          iVar9 = memcmp(plVar12,plVar14,_Size);
          if (iVar9 == 0) {
            lVar15 = *plVar4;
            plVar16 = (longlong *)plVar8[1];
            *plVar16 = (longlong)plVar3;
            plVar14 = (longlong *)plVar3[1];
            *plVar14 = lVar15;
            puVar17 = *(undefined8 **)(lVar15 + 8);
            *puVar17 = plVar8;
            *(longlong **)(lVar15 + 8) = plVar14;
            plVar3[1] = (longlong)plVar16;
            plVar8[1] = (longlong)puVar17;
            plVar8 = plVar3;
            goto joined_r0x000140028c43;
          }
          uVar10 = plVar8[5];
        }
      }
      plVar16 = (longlong *)plVar8[1];
      *plVar16 = (longlong)plVar3;
      puVar5 = (undefined8 *)plVar3[1];
      *puVar5 = plVar4;
      puVar6 = (undefined8 *)plVar4[1];
      *puVar6 = plVar8;
      plVar4[1] = (longlong)puVar5;
      plVar3[1] = (longlong)plVar16;
      plVar8[1] = (longlong)puVar6;
      *puVar17 = plVar8;
      plVar8 = plVar3;
      goto joined_r0x000140028c43;
    }
    iVar9 = memcmp(plVar12,plVar14,_Size);
    if (iVar9 != 0) {
      uVar10 = plVar8[5];
      goto joined_r0x000140028d44;
    }
    plVar4 = (longlong *)*plVar4;
    if (plVar4 != plVar8) {
      plVar16 = (longlong *)plVar8[1];
      *plVar16 = (longlong)plVar3;
      puVar5 = (undefined8 *)plVar3[1];
      *puVar5 = plVar4;
      puVar6 = (undefined8 *)plVar4[1];
      *puVar6 = plVar8;
      plVar4[1] = (longlong)puVar5;
      plVar3[1] = (longlong)plVar16;
      plVar8[1] = (longlong)puVar6;
    }
    puVar17[1] = plVar8;
    plVar8 = plVar3;
  } while( true );
}


// FUNCTION_END

// FUNCTION_START: FUN_140028e40 @ 140028e40