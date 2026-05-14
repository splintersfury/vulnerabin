void FUN_100208e2(void)

{
  char cVar1;
  void *pvVar2;
  int iVar3;
  code *pcVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  char *pcVar8;
  uint uVar9;
  undefined4 uVar10;
  undefined4 *puVar11;
  uint *puVar12;
  int *piVar13;
  int *piVar14;
  LPCWSTR pWVar15;
  char *extraout_ECX;
  char *extraout_ECX_00;
  char *extraout_ECX_01;
  byte *pbVar16;
  char *extraout_ECX_02;
  char *extraout_ECX_03;
  void *pvVar17;
  int *piVar18;
  uint *puVar19;
  uint unaff_EBP;
  undefined4 *puVar20;
  char *unaff_EDI;
  undefined4 *puVar21;
  uint unaff_retaddr;
  undefined4 uStack00000008;
  
  pcVar8 = FUN_100182c0((undefined4 *)(unaff_EBP - 0x5c));
  *(undefined4 *)(unaff_EBP - 0x44) = 0;
  *(undefined4 *)(unaff_EBP - 0x40) = 0;
  *(undefined4 *)(unaff_EBP - 0x3c) = 0;
  *(undefined4 *)(unaff_EBP - 0x38) = 0;
  FUN_100184e0(pcVar8,(undefined4 *)(unaff_EBP - 0x44));
  if (*extraout_ECX == '\x01') {
    puVar11 = (undefined4 *)**(int **)(extraout_ECX + 8);
    *(undefined4 **)(unaff_EBP - 0x84) = puVar11;
    cVar1 = *(char *)((int)puVar11[1] + 0xd);
    puVar21 = (undefined4 *)puVar11[1];
    while (cVar1 == '\0') {
      pbVar16 = (byte *)(puVar21 + 4);
      if (0xf < (uint)puVar21[9]) {
        pbVar16 = *(byte **)pbVar16;
      }
      uVar9 = FUN_100148a0(pbVar16,puVar21[8],(byte *)"protocol_handler",0x10);
      if ((int)uVar9 < 0) {
        puVar20 = (undefined4 *)puVar21[2];
        puVar21 = puVar11;
      }
      else {
        puVar20 = (undefined4 *)*puVar21;
      }
      puVar11 = puVar21;
      puVar21 = puVar20;
      cVar1 = *(char *)((int)puVar20 + 0xd);
    }
    if (*(char *)((int)puVar11 + 0xd) == '\0') {
      pbVar16 = (byte *)(puVar11 + 4);
      if (0xf < (uint)puVar11[9]) {
        pbVar16 = *(byte **)pbVar16;
      }
      uVar9 = FUN_100148a0(pbVar16,puVar11[8],(byte *)"protocol_handler",0x10);
      if (0 < (int)uVar9) goto LAB_10020977;
    }
    else {
LAB_10020977:
      puVar11 = *(undefined4 **)(unaff_EBP - 0x84);
    }
    *(undefined4 **)(unaff_EBP - 0x40) = puVar11;
    unaff_EDI = *(char **)(unaff_EBP - 0x88);
  }
  pcVar8 = FUN_100182c0((undefined4 *)(unaff_EBP - 0x5c));
  FUN_100184e0(pcVar8,(undefined4 *)(unaff_EBP - 0x2c));
  uVar10 = FUN_10018200((void *)(unaff_EBP - 0x44),(int *)(unaff_EBP - 0x2c));
  if (((char)uVar10 != '\0') &&
     (pcVar8 = FUN_100182c0((undefined4 *)(unaff_EBP - 0x44)), *pcVar8 == '\x01')) {
    pcVar8 = FUN_100182c0((undefined4 *)(unaff_EBP - 0x44));
    *(undefined4 *)(unaff_EBP - 0x5c) = 0;
    *(undefined4 *)(unaff_EBP - 0x58) = 0;
    *(undefined4 *)(unaff_EBP - 0x54) = 0;
    *(undefined4 *)(unaff_EBP - 0x50) = 0;
    FUN_100184e0(pcVar8,(undefined4 *)(unaff_EBP - 0x5c));
    if (*extraout_ECX_00 == '\x01') {
      puVar11 = (undefined4 *)
                FUN_10023d80(*(void **)(extraout_ECX_00 + 8),(int *)(unaff_EBP - 0x8c),&DAT_1005fdb0
                            );
      *(undefined4 *)(unaff_EBP - 0x58) = *puVar11;
    }
    pcVar8 = FUN_100182c0((undefined4 *)(unaff_EBP - 0x44));
    FUN_100184e0(pcVar8,(undefined4 *)(unaff_EBP - 0x2c));
    uVar10 = FUN_10018200((void *)(unaff_EBP - 0x5c),(int *)(unaff_EBP - 0x2c));
    if (((char)uVar10 == '\0') ||
       (pcVar8 = FUN_100182c0((undefined4 *)(unaff_EBP - 0x5c)), *pcVar8 != '\x03')) {
LAB_10020aa2:
      pcVar8 = FUN_100182c0((undefined4 *)(unaff_EBP - 0x44));
      FUN_100238e0(pcVar8,(undefined4 *)(unaff_EBP - 0x5c),(byte *)"description");
      pcVar8 = FUN_100182c0((undefined4 *)(unaff_EBP - 0x44));
      FUN_100184e0(pcVar8,(undefined4 *)(unaff_EBP - 0x2c));
      uVar10 = FUN_10018200((void *)(unaff_EBP - 0x5c),(int *)(unaff_EBP - 0x2c));
      if (((char)uVar10 != '\0') &&
         (pcVar8 = FUN_100182c0((undefined4 *)(unaff_EBP - 0x5c)), *pcVar8 == '\x03')) {
        pcVar8 = FUN_100182c0((undefined4 *)(unaff_EBP - 0x5c));
        puVar12 = FUN_100142f0(pcVar8,(uint *)(unaff_EBP - 0x34));
        *(undefined4 *)(unaff_EBP - 4) = 0x16;
        *(undefined4 *)(unaff_EBP - 0x84) = 0x1a;
        piVar13 = FUN_10021fc0(&DAT_1006b728,(int *)(unaff_EBP - 0x84));
        FUN_1000ec10(piVar13,(int *)puVar12);
        *(undefined4 *)(unaff_EBP - 4) = 0xffffffff;
        if (0xf < *(uint *)(unaff_EBP - 0x20)) {
          pvVar2 = *(void **)(unaff_EBP - 0x34);
          pvVar17 = pvVar2;
          if ((0xfff < *(uint *)(unaff_EBP - 0x20) + 1) &&
             (pvVar17 = *(void **)((int)pvVar2 + -4),
             0x1f < (uint)((int)pvVar2 + (-4 - (int)pvVar17)))) goto LAB_10021878;
          FUN_1002e346(pvVar17);
        }
      }
      pcVar8 = FUN_100182c0((undefined4 *)(unaff_EBP - 0x44));
      FUN_100238e0(pcVar8,(undefined4 *)(unaff_EBP - 0x5c),(byte *)"handler");
      pcVar8 = FUN_100182c0((undefined4 *)(unaff_EBP - 0x44));
      FUN_100184e0(pcVar8,(undefined4 *)(unaff_EBP - 0x2c));
      uVar10 = FUN_10018200((void *)(unaff_EBP - 0x5c),(int *)(unaff_EBP - 0x2c));
      if (((char)uVar10 != '\0') &&
         (pcVar8 = FUN_100182c0((undefined4 *)(unaff_EBP - 0x5c)), *pcVar8 == '\x03')) {
        pcVar8 = FUN_100182c0((undefined4 *)(unaff_EBP - 0x5c));
        puVar12 = FUN_100142f0(pcVar8,(uint *)(unaff_EBP - 0x34));
        *(undefined4 *)(unaff_EBP - 4) = 0x17;
        *(undefined4 *)(unaff_EBP - 0x84) = 0x1b;
        piVar13 = FUN_10021fc0(&DAT_1006b728,(int *)(unaff_EBP - 0x84));
        FUN_1000ec10(piVar13,(int *)puVar12);
        *(undefined4 *)(unaff_EBP - 4) = 0xffffffff;
        if (0xf < *(uint *)(unaff_EBP - 0x20)) {
          pvVar2 = *(void **)(unaff_EBP - 0x34);
          pvVar17 = pvVar2;
          if ((0xfff < *(uint *)(unaff_EBP - 0x20) + 1) &&
             (pvVar17 = *(void **)((int)pvVar2 + -4),
             0x1f < (uint)((int)pvVar2 + (-4 - (int)pvVar17)))) goto LAB_1002187d;
          FUN_1002e346(pvVar17);
        }
      }
      pcVar8 = FUN_100182c0((undefined4 *)(unaff_EBP - 0x44));
      *(undefined4 *)(unaff_EBP - 0x5c) = 0;
      *(undefined4 *)(unaff_EBP - 0x58) = 0;
      *(undefined4 *)(unaff_EBP - 0x54) = 0;
      *(undefined4 *)(unaff_EBP - 0x50) = 0;
      FUN_100184e0(pcVar8,(undefined4 *)(unaff_EBP - 0x5c));
      if (*extraout_ECX_01 == '\x01') {
        puVar11 = (undefined4 *)
                  FUN_10023d80(*(void **)(extraout_ECX_01 + 8),(int *)(unaff_EBP - 0x8c),
                               &DAT_10060280);
        *(undefined4 *)(unaff_EBP - 0x58) = *puVar11;
      }
      pcVar8 = FUN_100182c0((undefined4 *)(unaff_EBP - 0x44));
      FUN_100184e0(pcVar8,(undefined4 *)(unaff_EBP - 0x2c));
      uVar10 = FUN_10018200((void *)(unaff_EBP - 0x5c),(int *)(unaff_EBP - 0x2c));
      if (((char)uVar10 != '\0') &&
         (pcVar8 = FUN_100182c0((undefined4 *)(unaff_EBP - 0x5c)), *pcVar8 == '\x03')) {
        pcVar8 = FUN_100182c0((undefined4 *)(unaff_EBP - 0x5c));
        puVar12 = FUN_100142f0(pcVar8,(uint *)(unaff_EBP - 0x34));
        *(undefined4 *)(unaff_EBP - 4) = 0x18;
        *(undefined4 *)(unaff_EBP - 0x84) = 0x1c;
        piVar13 = FUN_10021fc0(&DAT_1006b728,(int *)(unaff_EBP - 0x84));
        FUN_1000ec10(piVar13,(int *)puVar12);
        *(undefined4 *)(unaff_EBP - 4) = 0xffffffff;
        if (0xf < *(uint *)(unaff_EBP - 0x20)) {
          pvVar2 = *(void **)(unaff_EBP - 0x34);
          pvVar17 = pvVar2;
          if ((0xfff < *(uint *)(unaff_EBP - 0x20) + 1) &&
             (pvVar17 = *(void **)((int)pvVar2 + -4),
             0x1f < (uint)((int)pvVar2 + (-4 - (int)pvVar17)))) goto LAB_10021882;
          FUN_1002e346(pvVar17);
        }
      }
      pcVar8 = FUN_100182c0((undefined4 *)(unaff_EBP - 0x44));
      FUN_100238e0(pcVar8,(undefined4 *)(unaff_EBP - 0x5c),(byte *)"redirect");
      pcVar8 = FUN_100182c0((undefined4 *)(unaff_EBP - 0x44));
      FUN_100184e0(pcVar8,(undefined4 *)(unaff_EBP - 0x2c));
      uVar10 = FUN_10018200((void *)(unaff_EBP - 0x5c),(int *)(unaff_EBP - 0x2c));
      if (((char)uVar10 != '\0') &&
         (pcVar8 = FUN_100182c0((undefined4 *)(unaff_EBP - 0x5c)), *pcVar8 == '\x03')) {
        pcVar8 = FUN_100182c0((undefined4 *)(unaff_EBP - 0x5c));
        puVar12 = FUN_100142f0(pcVar8,(uint *)(unaff_EBP - 0x34));
        *(undefined4 *)(unaff_EBP - 4) = 0x19;
        *(undefined4 *)(unaff_EBP - 0x84) = 0x1d;
        piVar13 = FUN_10021fc0(&DAT_1006b728,(int *)(unaff_EBP - 0x84));
        FUN_1000ec10(piVar13,(int *)puVar12);
        *(undefined4 *)(unaff_EBP - 4) = 0xffffffff;
        if (0xf < *(uint *)(unaff_EBP - 0x20)) {
          pvVar2 = *(void **)(unaff_EBP - 0x34);
          pvVar17 = pvVar2;
          if ((0xfff < *(uint *)(unaff_EBP - 0x20) + 1) &&
             (pvVar17 = *(void **)((int)pvVar2 + -4),
             0x1f < (uint)((int)pvVar2 + (-4 - (int)pvVar17)))) goto LAB_10021887;
          FUN_1002e346(pvVar17);
        }
      }
      pcVar8 = FUN_100182c0((undefined4 *)(unaff_EBP - 0x44));
      FUN_100239b0(pcVar8,(undefined4 *)(unaff_EBP - 0x5c));
      pcVar8 = FUN_100182c0((undefined4 *)(unaff_EBP - 0x44));
      FUN_100184e0(pcVar8,(undefined4 *)(unaff_EBP - 0x2c));
      uVar10 = FUN_10018200((void *)(unaff_EBP - 0x5c),(int *)(unaff_EBP - 0x2c));
      if (((char)uVar10 != '\0') &&
         (pcVar8 = FUN_100182c0((undefined4 *)(unaff_EBP - 0x5c)), *pcVar8 == '\x03')) {
        pcVar8 = FUN_100182c0((undefined4 *)(unaff_EBP - 0x5c));
        puVar12 = FUN_100142f0(pcVar8,(uint *)(unaff_EBP - 0x34));
        *(undefined4 *)(unaff_EBP - 4) = 0x1a;
        *(undefined4 *)(unaff_EBP - 0x84) = 0x1e;
        piVar13 = FUN_10021fc0(&DAT_1006b728,(int *)(unaff_EBP - 0x84));
        FUN_1000ec10(piVar13,(int *)puVar12);
        *(undefined4 *)(unaff_EBP - 4) = 0xffffffff;
        if (0xf < *(uint *)(unaff_EBP - 0x20)) {
          pvVar2 = *(void **)(unaff_EBP - 0x34);
          pvVar17 = pvVar2;
          if ((0xfff < *(uint *)(unaff_EBP - 0x20) + 1) &&
             (pvVar17 = *(void **)((int)pvVar2 + -4),
             0x1f < (uint)((int)pvVar2 + (-4 - (int)pvVar17)))) goto LAB_1002188c;
          FUN_1002e346(pvVar17);
        }
      }
      pcVar8 = FUN_100182c0((undefined4 *)(unaff_EBP - 0x44));
      FUN_100238e0(pcVar8,(undefined4 *)(unaff_EBP - 0x5c),(byte *)"redirect_id");
      pcVar8 = FUN_100182c0((undefined4 *)(unaff_EBP - 0x44));
      FUN_100184e0(pcVar8,(undefined4 *)(unaff_EBP - 0x2c));
      uVar10 = FUN_10018200((void *)(unaff_EBP - 0x5c),(int *)(unaff_EBP - 0x2c));
      if (((char)uVar10 != '\0') &&
         (pcVar8 = FUN_100182c0((undefined4 *)(unaff_EBP - 0x5c)), *pcVar8 == '\x03')) {
        pcVar8 = FUN_100182c0((undefined4 *)(unaff_EBP - 0x5c));
        puVar12 = FUN_100142f0(pcVar8,(uint *)(unaff_EBP - 0x34));
        *(undefined4 *)(unaff_EBP - 4) = 0x1b;
        *(undefined4 *)(unaff_EBP - 0x84) = 0x1f;
        piVar13 = FUN_10021fc0(&DAT_1006b728,(int *)(unaff_EBP - 0x84));
        FUN_1000ec10(piVar13,(int *)puVar12);
        *(undefined4 *)(unaff_EBP - 4) = 0xffffffff;
        if (0xf < *(uint *)(unaff_EBP - 0x20)) {
          pvVar2 = *(void **)(unaff_EBP - 0x34);
          pvVar17 = pvVar2;
          if ((0xfff < *(uint *)(unaff_EBP - 0x20) + 1) &&
             (pvVar17 = *(void **)((int)pvVar2 + -4),
             0x1f < (uint)((int)pvVar2 + (-4 - (int)pvVar17)))) goto LAB_10021891;
          FUN_1002e346(pvVar17);
        }
      }
      pcVar8 = FUN_100182c0((undefined4 *)(unaff_EBP - 0x44));
      FUN_100238e0(pcVar8,(undefined4 *)(unaff_EBP - 0x5c),(byte *)"signup_url");
      pcVar8 = FUN_100182c0((undefined4 *)(unaff_EBP - 0x44));
      FUN_100184e0(pcVar8,(undefined4 *)(unaff_EBP - 0x2c));
      uVar10 = FUN_10018200((void *)(unaff_EBP - 0x5c),(int *)(unaff_EBP - 0x2c));
      if (((char)uVar10 != '\0') &&
         (pcVar8 = FUN_100182c0((undefined4 *)(unaff_EBP - 0x5c)), *pcVar8 == '\x03')) {
        pcVar8 = FUN_100182c0((undefined4 *)(unaff_EBP - 0x5c));
        puVar12 = FUN_100142f0(pcVar8,(uint *)(unaff_EBP - 0x34));
        *(undefined4 *)(unaff_EBP - 4) = 0x1c;
        *(undefined4 *)(unaff_EBP - 0x84) = 0x20;
        piVar13 = FUN_10021fc0(&DAT_1006b728,(int *)(unaff_EBP - 0x84));
        FUN_1000ec10(piVar13,(int *)puVar12);
        *(undefined4 *)(unaff_EBP - 4) = 0xffffffff;
        if (0xf < *(uint *)(unaff_EBP - 0x20)) {
          pvVar2 = *(void **)(unaff_EBP - 0x34);
          pvVar17 = pvVar2;
          if ((0xfff < *(uint *)(unaff_EBP - 0x20) + 1) &&
             (pvVar17 = *(void **)((int)pvVar2 + -4),
             0x1f < (uint)((int)pvVar2 + (-4 - (int)pvVar17)))) goto LAB_10021896;
          FUN_1002e346(pvVar17);
        }
      }
      goto LAB_1002101a;
    }
    pcVar8 = FUN_100182c0((undefined4 *)(unaff_EBP - 0x5c));
    puVar12 = FUN_100142f0(pcVar8,(uint *)(unaff_EBP - 0x34));
    *(undefined4 *)(unaff_EBP - 4) = 0x15;
    *(undefined4 *)(unaff_EBP - 0x84) = 0x19;
    piVar13 = FUN_10021fc0(&DAT_1006b728,(int *)(unaff_EBP - 0x84));
    FUN_1000ec10(piVar13,(int *)puVar12);
    *(undefined4 *)(unaff_EBP - 4) = 0xffffffff;
    if (*(uint *)(unaff_EBP - 0x20) < 0x10) goto LAB_10020aa2;
    pvVar2 = *(void **)(unaff_EBP - 0x34);
    pvVar17 = pvVar2;
    if ((*(uint *)(unaff_EBP - 0x20) + 1 < 0x1000) ||
       (pvVar17 = *(void **)((int)pvVar2 + -4), (uint)((int)pvVar2 + (-4 - (int)pvVar17)) < 0x20)) {
      FUN_1002e346(pvVar17);
      goto LAB_10020aa2;
    }
    FUN_10032f7f();
LAB_10021878:
    FUN_10032f7f();
LAB_1002187d:
    FUN_10032f7f();
LAB_10021882:
    FUN_10032f7f();
LAB_10021887:
    FUN_10032f7f();
LAB_1002188c:
    FUN_10032f7f();
LAB_10021891:
    FUN_10032f7f();
LAB_10021896:
    FUN_10032f7f();
LAB_1002189b:
    FUN_10032f7f();
LAB_100218a0:
    FUN_10032f7f();
LAB_100218a5:
    FUN_10032f7f();
LAB_100218aa:
    FUN_10032f7f();
LAB_100218af:
    FUN_10032f7f();
LAB_100218b4:
    FUN_10032f7f();
    pcVar4 = (code *)swi(3);
    (*pcVar4)();
    return;
  }
LAB_1002101a:
  *(undefined4 *)(unaff_EBP - 0x44) = 0;
  *(undefined4 *)(unaff_EBP - 0x40) = 0;
  *(undefined4 *)(unaff_EBP - 0x3c) = 0;
  *(undefined4 *)(unaff_EBP - 0x38) = 0;
  FUN_100184e0(unaff_EDI,(undefined4 *)(unaff_EBP - 0x44));
  if (*unaff_EDI == '\x01') {
    puVar11 = (undefined4 *)**(int **)(unaff_EDI + 8);
    *(undefined4 **)(unaff_EBP - 0x84) = puVar11;
    cVar1 = *(char *)((int)puVar11[1] + 0xd);
    puVar21 = (undefined4 *)puVar11[1];
    while (cVar1 == '\0') {
      pbVar16 = (byte *)(puVar21 + 4);
      if (0xf < (uint)puVar21[9]) {
        pbVar16 = *(byte **)pbVar16;
      }
      uVar9 = FUN_100148a0(pbVar16,puVar21[8],&DAT_10060304,2);
      if ((int)uVar9 < 0) {
        puVar20 = (undefined4 *)puVar21[2];
        puVar21 = puVar11;
      }
      else {
        puVar20 = (undefined4 *)*puVar21;
      }
      puVar11 = puVar21;
      puVar21 = puVar20;
      cVar1 = *(char *)((int)puVar20 + 0xd);
    }
    if (*(char *)((int)puVar11 + 0xd) == '\0') {
      pbVar16 = (byte *)(puVar11 + 4);
      if (0xf < (uint)puVar11[9]) {
        pbVar16 = *(byte **)pbVar16;
      }
      uVar9 = FUN_100148a0(pbVar16,puVar11[8],&DAT_10060304,2);
      if (0 < (int)uVar9) goto LAB_100210a7;
    }
    else {
LAB_100210a7:
      puVar11 = *(undefined4 **)(unaff_EBP - 0x84);
    }
    *(undefined4 **)(unaff_EBP - 0x40) = puVar11;
    unaff_EDI = *(char **)(unaff_EBP - 0x88);
  }
  FUN_100184e0(unaff_EDI,(undefined4 *)(unaff_EBP - 0x2c));
  uVar10 = FUN_10018200((void *)(unaff_EBP - 0x44),(int *)(unaff_EBP - 0x2c));
  if (((char)uVar10 != '\0') &&
     (pcVar8 = FUN_100182c0((undefined4 *)(unaff_EBP - 0x44)), *pcVar8 == '\x01')) {
    pcVar8 = FUN_100182c0((undefined4 *)(unaff_EBP - 0x44));
    FUN_100238e0(pcVar8,(undefined4 *)(unaff_EBP - 0x5c),(byte *)"about_reg_path");
    pcVar8 = FUN_100182c0((undefined4 *)(unaff_EBP - 0x44));
    FUN_100184e0(pcVar8,(undefined4 *)(unaff_EBP - 0x2c));
    uVar10 = FUN_10018200((void *)(unaff_EBP - 0x5c),(int *)(unaff_EBP - 0x2c));
    if (((char)uVar10 != '\0') &&
       (pcVar8 = FUN_100182c0((undefined4 *)(unaff_EBP - 0x5c)), *pcVar8 == '\x03')) {
      pcVar8 = FUN_100182c0((undefined4 *)(unaff_EBP - 0x5c));
      puVar12 = FUN_100142f0(pcVar8,(uint *)(unaff_EBP - 0x34));
      *(undefined4 *)(unaff_EBP - 4) = 0x1d;
      *(undefined4 *)(unaff_EBP - 0x84) = 0x22;
      piVar13 = FUN_10021fc0(&DAT_1006b728,(int *)(unaff_EBP - 0x84));
      FUN_1000ec10(piVar13,(int *)puVar12);
      *(undefined4 *)(unaff_EBP - 4) = 0xffffffff;
      if (0xf < *(uint *)(unaff_EBP - 0x20)) {
        pvVar2 = *(void **)(unaff_EBP - 0x34);
        pvVar17 = pvVar2;
        if ((0xfff < *(uint *)(unaff_EBP - 0x20) + 1) &&
           (pvVar17 = *(void **)((int)pvVar2 + -4), 0x1f < (uint)((int)pvVar2 + (-4 - (int)pvVar17))
           )) goto LAB_1002189b;
        FUN_1002e346(pvVar17);
      }
    }
    pcVar8 = FUN_100182c0((undefined4 *)(unaff_EBP - 0x44));
    *(undefined4 *)(unaff_EBP - 0x5c) = 0;
    *(undefined4 *)(unaff_EBP - 0x58) = 0;
    *(undefined4 *)(unaff_EBP - 0x54) = 0;
    *(undefined4 *)(unaff_EBP - 0x50) = 0;
    FUN_100184e0(pcVar8,(undefined4 *)(unaff_EBP - 0x5c));
    if (*extraout_ECX_02 == '\x01') {
      puVar11 = (undefined4 *)
                FUN_10023d80(*(void **)(extraout_ECX_02 + 8),(int *)(unaff_EBP - 0x8c),&DAT_10060318
                            );
      *(undefined4 *)(unaff_EBP - 0x58) = *puVar11;
    }
    pcVar8 = FUN_100182c0((undefined4 *)(unaff_EBP - 0x44));
    FUN_100184e0(pcVar8,(undefined4 *)(unaff_EBP - 0x2c));
    uVar10 = FUN_10018200((void *)(unaff_EBP - 0x5c),(int *)(unaff_EBP - 0x2c));
    if (((char)uVar10 != '\0') &&
       (pcVar8 = FUN_100182c0((undefined4 *)(unaff_EBP - 0x5c)), *pcVar8 == '\x01')) {
      pcVar8 = FUN_100182c0((undefined4 *)(unaff_EBP - 0x5c));
      FUN_100238e0(pcVar8,(undefined4 *)(unaff_EBP - 0x2c),(byte *)"install_path");
      pcVar8 = FUN_100182c0((undefined4 *)(unaff_EBP - 0x5c));
      FUN_100184e0(pcVar8,(undefined4 *)(unaff_EBP - 0x5c));
      uVar10 = FUN_10018200((void *)(unaff_EBP - 0x2c),(int *)(unaff_EBP - 0x5c));
      if (((char)uVar10 != '\0') &&
         (pcVar8 = FUN_100182c0((undefined4 *)(unaff_EBP - 0x2c)), *pcVar8 == '\x03')) {
        pcVar8 = FUN_100182c0((undefined4 *)(unaff_EBP - 0x2c));
        puVar12 = FUN_100142f0(pcVar8,(uint *)(unaff_EBP - 100));
        *(undefined4 *)(unaff_EBP - 4) = 0x1e;
        *(undefined4 *)(unaff_EBP - 0x84) = 0x23;
        piVar13 = FUN_10021fc0(&DAT_1006b728,(int *)(unaff_EBP - 0x84));
        FUN_1000ec10(piVar13,(int *)puVar12);
        *(undefined4 *)(unaff_EBP - 4) = 0xffffffff;
        if (0xf < *(uint *)(unaff_EBP - 0x50)) {
          pvVar2 = *(void **)(unaff_EBP - 100);
          pvVar17 = pvVar2;
          if ((0xfff < *(uint *)(unaff_EBP - 0x50) + 1) &&
             (pvVar17 = *(void **)((int)pvVar2 + -4),
             0x1f < (uint)((int)pvVar2 + (-4 - (int)pvVar17)))) goto LAB_100218a0;
          FUN_1002e346(pvVar17);
        }
      }
    }
    pcVar8 = FUN_100182c0((undefined4 *)(unaff_EBP - 0x44));
    *(undefined4 *)(unaff_EBP - 0x5c) = 0;
    *(undefined4 *)(unaff_EBP - 0x58) = 0;
    *(undefined4 *)(unaff_EBP - 0x54) = 0;
    *(undefined4 *)(unaff_EBP - 0x50) = 0;
    FUN_100184e0(pcVar8,(undefined4 *)(unaff_EBP - 0x5c));
    if (*extraout_ECX_03 == '\x01') {
      puVar11 = (undefined4 *)
                FUN_10023d80(*(void **)(extraout_ECX_03 + 8),(int *)(unaff_EBP - 0x8c),&DAT_1006032c
                            );
      *(undefined4 *)(unaff_EBP - 0x58) = *puVar11;
    }
    pcVar8 = FUN_100182c0((undefined4 *)(unaff_EBP - 0x44));
    FUN_100184e0(pcVar8,(undefined4 *)(unaff_EBP - 0x2c));
    uVar10 = FUN_10018200((void *)(unaff_EBP - 0x5c),(int *)(unaff_EBP - 0x2c));
    if (((char)uVar10 != '\0') &&
       (pcVar8 = FUN_100182c0((undefined4 *)(unaff_EBP - 0x5c)), *pcVar8 == '\x01')) {
      pcVar8 = FUN_100182c0((undefined4 *)(unaff_EBP - 0x5c));
      FUN_100238e0(pcVar8,(undefined4 *)(unaff_EBP - 0x2c),(byte *)"install_path");
      pcVar8 = FUN_100182c0((undefined4 *)(unaff_EBP - 0x5c));
      FUN_100184e0(pcVar8,(undefined4 *)(unaff_EBP - 0x44));
      uVar10 = FUN_10018200((void *)(unaff_EBP - 0x2c),(int *)(unaff_EBP - 0x44));
      if (((char)uVar10 != '\0') &&
         (pcVar8 = FUN_100182c0((undefined4 *)(unaff_EBP - 0x2c)), *pcVar8 == '\x03')) {
        pcVar8 = FUN_100182c0((undefined4 *)(unaff_EBP - 0x2c));
        puVar12 = FUN_100142f0(pcVar8,(uint *)(unaff_EBP - 0x4c));
        *(undefined4 *)(unaff_EBP - 4) = 0x1f;
        *(undefined4 *)(unaff_EBP - 0x84) = 0x24;
        piVar13 = FUN_10021fc0(&DAT_1006b728,(int *)(unaff_EBP - 0x84));
        FUN_1000ec10(piVar13,(int *)puVar12);
        *(undefined4 *)(unaff_EBP - 4) = 0xffffffff;
        if (0xf < *(uint *)(unaff_EBP - 0x38)) {
          pvVar2 = *(void **)(unaff_EBP - 0x4c);
          pvVar17 = pvVar2;
          if ((0xfff < *(uint *)(unaff_EBP - 0x38) + 1) &&
             (pvVar17 = *(void **)((int)pvVar2 + -4),
             0x1f < (uint)((int)pvVar2 + (-4 - (int)pvVar17)))) goto LAB_100218a5;
          FUN_1002e346(pvVar17);
        }
      }
    }
  }
  FUN_100238e0(unaff_EDI,(undefined4 *)(unaff_EBP - 0x44),(byte *)"bucket_testing");
  FUN_100184e0(unaff_EDI,(undefined4 *)(unaff_EBP - 0x2c));
  uVar10 = FUN_10018200((void *)(unaff_EBP - 0x44),(int *)(unaff_EBP - 0x2c));
  if (((char)uVar10 != '\0') &&
     (pcVar8 = FUN_100182c0((undefined4 *)(unaff_EBP - 0x44)), *pcVar8 == '\x01')) {
    pcVar8 = FUN_100182c0((undefined4 *)(unaff_EBP - 0x44));
    FUN_100238e0(pcVar8,(undefined4 *)(unaff_EBP - 0x2c),(byte *)"app_id");
    pcVar8 = FUN_100182c0((undefined4 *)(unaff_EBP - 0x44));
    FUN_100184e0(pcVar8,(undefined4 *)(unaff_EBP - 0x44));
    uVar10 = FUN_10018200((void *)(unaff_EBP - 0x2c),(int *)(unaff_EBP - 0x44));
    if (((char)uVar10 != '\0') &&
       (pcVar8 = FUN_100182c0((undefined4 *)(unaff_EBP - 0x2c)), *pcVar8 == '\x03')) {
      pcVar8 = FUN_100182c0((undefined4 *)(unaff_EBP - 0x2c));
      puVar12 = FUN_100142f0(pcVar8,(uint *)(unaff_EBP - 0x4c));
      *(undefined4 *)(unaff_EBP - 4) = 0x20;
      *(undefined4 *)(unaff_EBP - 0x84) = 0x25;
      piVar13 = FUN_10021fc0(&DAT_1006b728,(int *)(unaff_EBP - 0x84));
      FUN_1000ec10(piVar13,(int *)puVar12);
      *(undefined4 *)(unaff_EBP - 4) = 0xffffffff;
      if (0xf < *(uint *)(unaff_EBP - 0x38)) {
        pvVar2 = *(void **)(unaff_EBP - 0x4c);
        pvVar17 = pvVar2;
        if ((0xfff < *(uint *)(unaff_EBP - 0x38) + 1) &&
           (pvVar17 = *(void **)((int)pvVar2 + -4), 0x1f < (uint)((int)pvVar2 + (-4 - (int)pvVar17))
           )) goto LAB_100218aa;
        FUN_1002e346(pvVar17);
      }
    }
  }
  piVar13 = (int *)*DAT_1006b728;
  if (piVar13 != DAT_1006b728) {
    do {
      piVar18 = piVar13 + 5;
      if (0xf < (uint)piVar13[10]) {
        piVar18 = (int *)*piVar18;
      }
      FUN_1001c8a0((void *)(unaff_EBP - 0x34),(LPCSTR)piVar18,unaff_retaddr);
      piVar18 = (int *)(unaff_EBP - 0x34);
      *(undefined4 *)(unaff_EBP - 4) = 0x21;
      piVar14 = FUN_10022090(&DAT_1006b720,piVar13 + 4);
      FUN_10005380(piVar14,piVar18);
      *(undefined4 *)(unaff_EBP - 4) = 0xffffffff;
      if (7 < *(uint *)(unaff_EBP - 0x20)) {
        pvVar2 = *(void **)(unaff_EBP - 0x34);
        pvVar17 = pvVar2;
        if ((0xfff < *(uint *)(unaff_EBP - 0x20) * 2 + 2) &&
           (pvVar17 = *(void **)((int)pvVar2 + -4), 0x1f < (uint)((int)pvVar2 + (-4 - (int)pvVar17))
           )) goto LAB_100218b4;
        FUN_1002e346(pvVar17);
      }
      piVar18 = (int *)piVar13[2];
      if (*(char *)((int)piVar18 + 0xd) == '\0') {
        cVar1 = *(char *)(*piVar18 + 0xd);
        piVar13 = piVar18;
        piVar18 = (int *)*piVar18;
        while (cVar1 == '\0') {
          cVar1 = *(char *)(*piVar18 + 0xd);
          piVar13 = piVar18;
          piVar18 = (int *)*piVar18;
        }
      }
      else {
        cVar1 = *(char *)(piVar13[1] + 0xd);
        piVar14 = (int *)piVar13[1];
        piVar18 = piVar13;
        while ((piVar13 = piVar14, cVar1 == '\0' && (piVar18 == (int *)piVar13[2]))) {
          cVar1 = *(char *)(piVar13[1] + 0xd);
          piVar14 = (int *)piVar13[1];
          piVar18 = piVar13;
        }
      }
    } while (piVar13 != DAT_1006b728);
  }
  *(undefined4 *)(unaff_EBP - 0x84) = 6;
  pWVar15 = (LPCWSTR)FUN_10022090(&DAT_1006b720,(int *)(unaff_EBP - 0x84));
  if (7 < *(uint *)(pWVar15 + 10)) {
    pWVar15 = *(LPCWSTR *)pWVar15;
  }
  FUN_1001cec0((undefined4 *)(unaff_EBP - 0x80),pWVar15);
  *(undefined4 *)(unaff_EBP - 4) = 0x22;
  pWVar15 = (LPCWSTR)(unaff_EBP - 0x80);
  if (7 < *(uint *)(unaff_EBP - 0x6c)) {
    pWVar15 = *(LPCWSTR *)(unaff_EBP - 0x80);
  }
  FUN_1001c850((void *)(unaff_EBP - 0x34),pWVar15);
  *(undefined1 *)(unaff_EBP - 4) = 0x23;
  *(undefined4 *)(unaff_EBP - 0x88) = 0x14;
  piVar13 = FUN_10021fc0(&DAT_1006b728,(int *)(unaff_EBP - 0x88));
  if (piVar13 == (int *)(unaff_EBP - 0x34)) {
    uVar9 = *(uint *)(unaff_EBP - 0x20);
  }
  else {
    if (0xf < (uint)piVar13[5]) {
      pvVar2 = (void *)*piVar13;
      pvVar17 = pvVar2;
      if ((0xfff < piVar13[5] + 1U) &&
         (pvVar17 = *(void **)((int)pvVar2 + -4), 0x1f < (uint)((int)pvVar2 + (-4 - (int)pvVar17))))
      goto LAB_100218af;
      FUN_1002e346(pvVar17);
    }
    iVar3 = *(int *)(unaff_EBP - 0x34);
    iVar5 = *(int *)(unaff_EBP - 0x30);
    iVar6 = *(int *)(unaff_EBP - 0x2c);
    iVar7 = *(int *)(unaff_EBP - 0x28);
    uVar9 = 0xf;
    *(undefined1 *)(unaff_EBP - 0x34) = 0;
    *piVar13 = iVar3;
    piVar13[1] = iVar5;
    piVar13[2] = iVar6;
    piVar13[3] = iVar7;
    *(undefined8 *)(piVar13 + 4) = *(undefined8 *)(unaff_EBP - 0x24);
  }
  *(undefined1 *)(unaff_EBP - 4) = 0x22;
  if (0xf < uVar9) {
    pvVar2 = *(void **)(unaff_EBP - 0x34);
    pvVar17 = pvVar2;
    if ((0xfff < uVar9 + 1) &&
       (pvVar17 = *(void **)((int)pvVar2 + -4), 0x1f < (uint)((int)pvVar2 + (-4 - (int)pvVar17))))
    goto LAB_100218af;
    FUN_1002e346(pvVar17);
  }
  iVar3 = *(int *)(unaff_EBP - 0x68);
  puVar12 = (uint *)&DAT_100600c4;
  *(undefined4 *)(unaff_EBP - 0x88) = 0x15;
  if (iVar3 != 0) {
    puVar12 = (uint *)&DAT_10060340;
  }
  piVar13 = FUN_10021fc0(&DAT_1006b728,(int *)(unaff_EBP - 0x88));
  puVar19 = puVar12;
  do {
    uVar9 = *puVar19;
    puVar19 = (uint *)((int)puVar19 + 1);
  } while ((char)uVar9 != '\0');
  FUN_10008e70(piVar13,puVar12,(int)puVar19 - ((int)puVar12 + 1));
  *(undefined4 *)(unaff_EBP - 0x88) = 0x14;
  puVar12 = (uint *)FUN_10022090(&DAT_1006b720,(int *)(unaff_EBP - 0x88));
  if (puVar12 != (uint *)(unaff_EBP - 0x80)) {
    puVar19 = (uint *)(unaff_EBP - 0x80);
    if (7 < *(uint *)(unaff_EBP - 0x6c)) {
      puVar19 = *(uint **)(unaff_EBP - 0x80);
    }
    FUN_10001d40(puVar12,puVar19,*(uint *)(unaff_EBP - 0x70));
  }
  iVar3 = *(int *)(unaff_EBP - 0x68);
  puVar12 = (uint *)&DAT_10060344;
  *(undefined4 *)(unaff_EBP - 0x8c) = 0x15;
  if (iVar3 != 0) {
    puVar12 = (uint *)&DAT_1006034c;
  }
  piVar13 = FUN_10022090(&DAT_1006b720,(int *)(unaff_EBP - 0x8c));
  puVar19 = puVar12;
  do {
    uVar9 = *puVar19;
    puVar19 = (uint *)((int)puVar19 + 2);
  } while ((short)uVar9 != 0);
  FUN_10001d40(piVar13,puVar12,(int)puVar19 - ((int)puVar12 + 2) >> 1);
  if (7 < *(uint *)(unaff_EBP - 0x6c)) {
    pvVar2 = *(void **)(unaff_EBP - 0x80);
    pvVar17 = pvVar2;
    if ((0xfff < *(uint *)(unaff_EBP - 0x6c) * 2 + 2) &&
       (pvVar17 = *(void **)((int)pvVar2 + -4), 0x1f < (uint)((int)pvVar2 + (-4 - (int)pvVar17))))
    goto LAB_100218b4;
    FUN_1002e346(pvVar17);
  }
  ExceptionList = *(void **)(unaff_EBP - 0xc);
  uStack00000008 = 0x1002180b;
  FUN_1002e315(*(uint *)(unaff_EBP - 0x1c) ^ unaff_EBP);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_100218c0 @ 100218c0

/* WARNING: Removing unreachable block (ram,0x10021b08) */