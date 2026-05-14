void FUN_1001f880(char *param_1)

{
  char cVar1;
  code *pcVar2;
  int *piVar3;
  uint uVar4;
  undefined4 uVar5;
  char *pcVar6;
  undefined4 *puVar7;
  uint *puVar8;
  int *piVar9;
  uint uVar10;
  int *piVar11;
  LPCWSTR pWVar12;
  void **ppvVar13;
  LPCWSTR ****pppppWVar14;
  char *extraout_ECX;
  char *extraout_ECX_00;
  char *extraout_ECX_01;
  char *extraout_ECX_02;
  char *extraout_ECX_03;
  byte *pbVar15;
  char *extraout_ECX_04;
  char *extraout_ECX_05;
  void *pvVar16;
  char *extraout_ECX_06;
  char *extraout_ECX_07;
  void *pvVar17;
  LPCWSTR ****pppppWVar18;
  uint *puVar19;
  undefined4 *puVar20;
  undefined4 *puVar21;
  int local_9c;
  char *local_98;
  undefined4 *local_94;
  LPCWSTR ***appppWStack_90 [4];
  uint uStack_80;
  uint uStack_7c;
  int iStack_78;
  void *apvStack_74 [2];
  int local_6c;
  undefined4 uStack_68;
  undefined4 uStack_64;
  uint uStack_60;
  void *apvStack_5c [2];
  int local_54;
  undefined4 *puStack_50;
  undefined4 uStack_4c;
  uint uStack_48;
  void *local_44;
  void *pvStack_40;
  void *local_3c;
  void *pvStack_38;
  undefined4 uStack_34;
  uint local_30;
  uint local_2c;
  undefined1 *puStack_24;
  undefined1 *local_20;
  void *local_1c;
  undefined1 *puStack_18;
  undefined4 local_14;
  
  puStack_24 = &stack0xfffffffc;
  local_14 = 0xffffffff;
  puStack_18 = &LAB_1004fd95;
  local_1c = ExceptionList;
  uVar4 = DAT_10069054 ^ (uint)&stack0xfffffff0;
  local_20 = &stack0xffffff58;
  ExceptionList = &local_1c;
  local_98 = param_1;
  local_2c = uVar4;
  FUN_100238e0(param_1,&local_54,(byte *)"service");
  FUN_100184e0(param_1,&local_3c);
  uVar5 = FUN_10018200(&local_54,(int *)&local_3c);
  if (((char)uVar5 != '\0') && (pcVar6 = FUN_100182c0(&local_54), *pcVar6 == '\x01')) {
    pcVar6 = FUN_100182c0(&local_54);
    local_6c = 0;
    uStack_68 = 0;
    uStack_64 = 0;
    uStack_60 = 0;
    FUN_100184e0(pcVar6,&local_6c);
    if (*extraout_ECX == '\x01') {
      puVar7 = (undefined4 *)FUN_10023d80(*(void **)(extraout_ECX + 8),&local_9c,&DAT_1005fdb0);
      uStack_68 = *puVar7;
    }
    pcVar6 = FUN_100182c0(&local_54);
    FUN_100184e0(pcVar6,&local_3c);
    uVar5 = FUN_10018200(&local_6c,(int *)&local_3c);
    if (((char)uVar5 == '\0') || (pcVar6 = FUN_100182c0(&local_6c), *pcVar6 != '\x03')) {
LAB_1001f9ef:
      pcVar6 = FUN_100182c0(&local_54);
      FUN_100238e0(pcVar6,&local_6c,(byte *)"description");
      pcVar6 = FUN_100182c0(&local_54);
      FUN_100184e0(pcVar6,&local_3c);
      uVar5 = FUN_10018200(&local_6c,(int *)&local_3c);
      if (((char)uVar5 != '\0') && (pcVar6 = FUN_100182c0(&local_6c), *pcVar6 == '\x03')) {
        pcVar6 = FUN_100182c0(&local_6c);
        puVar8 = FUN_100142f0(pcVar6,(uint *)&local_44);
        local_14 = 1;
        local_94 = (undefined4 *)0x2;
        piVar9 = FUN_10021fc0(&DAT_1006b728,(int *)&local_94);
        FUN_1000ec10(piVar9,(int *)puVar8);
        local_14 = 0xffffffff;
        if (0xf < local_30) {
          pvVar16 = local_44;
          if ((0xfff < local_30 + 1) &&
             (pvVar16 = *(void **)((int)local_44 + -4),
             0x1f < (uint)((int)local_44 + (-4 - (int)pvVar16)))) goto LAB_10021819;
          FUN_1002e346(pvVar16);
        }
      }
      pcVar6 = FUN_100182c0(&local_54);
      FUN_100238e0(pcVar6,&local_6c,(byte *)"display_name");
      pcVar6 = FUN_100182c0(&local_54);
      FUN_100184e0(pcVar6,&local_3c);
      uVar5 = FUN_10018200(&local_6c,(int *)&local_3c);
      if (((char)uVar5 != '\0') && (pcVar6 = FUN_100182c0(&local_6c), *pcVar6 == '\x03')) {
        pcVar6 = FUN_100182c0(&local_6c);
        puVar8 = FUN_100142f0(pcVar6,(uint *)&local_44);
        local_14 = 2;
        local_94 = (undefined4 *)0x3;
        piVar9 = FUN_10021fc0(&DAT_1006b728,(int *)&local_94);
        FUN_1000ec10(piVar9,(int *)puVar8);
        local_14 = 0xffffffff;
        if (0xf < local_30) {
          pvVar16 = local_44;
          if ((0xfff < local_30 + 1) &&
             (pvVar16 = *(void **)((int)local_44 + -4),
             0x1f < (uint)((int)local_44 + (-4 - (int)pvVar16)))) goto LAB_1002181e;
          FUN_1002e346(pvVar16);
        }
      }
      goto LAB_1001fb77;
    }
    pcVar6 = FUN_100182c0(&local_6c);
    puVar8 = FUN_100142f0(pcVar6,(uint *)&local_44);
    local_14 = 0;
    local_94 = (undefined4 *)0x1;
    piVar9 = FUN_10021fc0(&DAT_1006b728,(int *)&local_94);
    FUN_1000ec10(piVar9,(int *)puVar8);
    local_14 = 0xffffffff;
    if (local_30 < 0x10) goto LAB_1001f9ef;
    pvVar16 = local_44;
    if ((local_30 + 1 < 0x1000) ||
       (pvVar16 = *(void **)((int)local_44 + -4), (uint)((int)local_44 + (-4 - (int)pvVar16)) < 0x20
       )) {
      FUN_1002e346(pvVar16);
      goto LAB_1001f9ef;
    }
    FUN_10032f7f();
LAB_10021819:
    FUN_10032f7f();
LAB_1002181e:
    FUN_10032f7f();
LAB_10021823:
    FUN_10032f7f();
LAB_10021828:
    FUN_10032f7f();
LAB_1002182d:
    FUN_10032f7f();
LAB_10021832:
    FUN_10032f7f();
LAB_10021837:
    FUN_10032f7f();
LAB_1002183c:
    FUN_10032f7f();
LAB_10021841:
    FUN_10032f7f();
LAB_10021846:
    FUN_10032f7f();
LAB_1002184b:
    FUN_10032f7f();
LAB_10021850:
    FUN_10032f7f();
LAB_10021855:
    FUN_10032f7f();
LAB_1002185a:
    FUN_10032f7f();
LAB_1002185f:
    FUN_10032f7f();
LAB_10021864:
    FUN_10032f7f();
LAB_10021869:
    FUN_10032f7f();
LAB_1002186e:
    FUN_10032f7f();
LAB_10021873:
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
    pcVar2 = (code *)swi(3);
    (*pcVar2)();
    return;
  }
LAB_1001fb77:
  FUN_100238e0(param_1,&local_54,(byte *)"partner_id");
  FUN_100184e0(param_1,&local_3c);
  uVar5 = FUN_10018200(&local_54,(int *)&local_3c);
  if (((char)uVar5 != '\0') && (pcVar6 = FUN_100182c0(&local_54), *pcVar6 == '\x03')) {
    pcVar6 = FUN_100182c0(&local_54);
    puVar8 = FUN_100142f0(pcVar6,(uint *)&local_44);
    local_14 = 3;
    local_94 = (undefined4 *)0x4;
    piVar9 = FUN_10021fc0(&DAT_1006b728,(int *)&local_94);
    FUN_1000ec10(piVar9,(int *)puVar8);
    local_14 = 0xffffffff;
    if (0xf < local_30) {
      pvVar16 = local_44;
      if ((0xfff < local_30 + 1) &&
         (pvVar16 = *(void **)((int)local_44 + -4),
         0x1f < (uint)((int)local_44 + (-4 - (int)pvVar16)))) goto LAB_10021823;
      FUN_1002e346(pvVar16);
    }
  }
  FUN_100238e0(param_1,&local_54,(byte *)"app_id");
  FUN_100184e0(param_1,&local_3c);
  uVar5 = FUN_10018200(&local_54,(int *)&local_3c);
  if (((char)uVar5 != '\0') && (pcVar6 = FUN_100182c0(&local_54), *pcVar6 == '\x03')) {
    pcVar6 = FUN_100182c0(&local_54);
    puVar8 = FUN_100142f0(pcVar6,(uint *)&local_44);
    local_14 = 4;
    local_94 = (undefined4 *)0x5;
    piVar9 = FUN_10021fc0(&DAT_1006b728,(int *)&local_94);
    FUN_1000ec10(piVar9,(int *)puVar8);
    local_14 = 0xffffffff;
    if (0xf < local_30) {
      pvVar16 = local_44;
      if ((0xfff < local_30 + 1) &&
         (pvVar16 = *(void **)((int)local_44 + -4),
         0x1f < (uint)((int)local_44 + (-4 - (int)pvVar16)))) goto LAB_10021828;
      FUN_1002e346(pvVar16);
    }
  }
  FUN_100238e0(param_1,&local_54,(byte *)"regpath");
  FUN_100184e0(param_1,&local_3c);
  uVar5 = FUN_10018200(&local_54,(int *)&local_3c);
  if (((char)uVar5 != '\0') && (pcVar6 = FUN_100182c0(&local_54), *pcVar6 == '\x01')) {
    pcVar6 = FUN_100182c0(&local_54);
    FUN_100238e0(pcVar6,&local_6c,(byte *)"product");
    pcVar6 = FUN_100182c0(&local_54);
    FUN_100184e0(pcVar6,&local_3c);
    uVar5 = FUN_10018200(&local_6c,(int *)&local_3c);
    if (((char)uVar5 != '\0') && (pcVar6 = FUN_100182c0(&local_6c), *pcVar6 == '\x03')) {
      pcVar6 = FUN_100182c0(&local_6c);
      puVar8 = FUN_100142f0(pcVar6,(uint *)&local_44);
      local_14 = 5;
      local_94 = (undefined4 *)0x6;
      piVar9 = FUN_10021fc0(&DAT_1006b728,(int *)&local_94);
      FUN_1000ec10(piVar9,(int *)puVar8);
      local_14 = 0xffffffff;
      if (0xf < local_30) {
        pvVar16 = local_44;
        if ((0xfff < local_30 + 1) &&
           (pvVar16 = *(void **)((int)local_44 + -4),
           0x1f < (uint)((int)local_44 + (-4 - (int)pvVar16)))) goto LAB_1002182d;
        FUN_1002e346(pvVar16);
      }
    }
    pcVar6 = FUN_100182c0(&local_54);
    FUN_100238e0(pcVar6,&local_6c,(byte *)"modules");
    pcVar6 = FUN_100182c0(&local_54);
    FUN_100184e0(pcVar6,&local_3c);
    uVar5 = FUN_10018200(&local_6c,(int *)&local_3c);
    if (((char)uVar5 != '\0') && (pcVar6 = FUN_100182c0(&local_6c), *pcVar6 == '\x03')) {
      pcVar6 = FUN_100182c0(&local_6c);
      puVar8 = FUN_100142f0(pcVar6,(uint *)&local_44);
      local_14 = 6;
      local_94 = (undefined4 *)0x7;
      piVar9 = FUN_10021fc0(&DAT_1006b728,(int *)&local_94);
      FUN_1000ec10(piVar9,(int *)puVar8);
      local_14 = 0xffffffff;
      if (0xf < local_30) {
        pvVar16 = local_44;
        if ((0xfff < local_30 + 1) &&
           (pvVar16 = *(void **)((int)local_44 + -4),
           0x1f < (uint)((int)local_44 + (-4 - (int)pvVar16)))) goto LAB_10021832;
        FUN_1002e346(pvVar16);
      }
    }
  }
  FUN_100238e0(param_1,&local_54,(byte *)"update");
  FUN_100184e0(param_1,&local_3c);
  uVar5 = FUN_10018200(&local_54,(int *)&local_3c);
  if (((char)uVar5 != '\0') && (pcVar6 = FUN_100182c0(&local_54), *pcVar6 == '\x03')) {
    pcVar6 = FUN_100182c0(&local_54);
    puVar8 = FUN_100142f0(pcVar6,(uint *)&local_44);
    local_14 = 7;
    local_94 = (undefined4 *)0x8;
    piVar9 = FUN_10021fc0(&DAT_1006b728,(int *)&local_94);
    FUN_1000ec10(piVar9,(int *)puVar8);
    local_14 = 0xffffffff;
    if (0xf < local_30) {
      pvVar16 = local_44;
      if ((0xfff < local_30 + 1) &&
         (pvVar16 = *(void **)((int)local_44 + -4),
         0x1f < (uint)((int)local_44 + (-4 - (int)pvVar16)))) goto LAB_10021837;
      FUN_1002e346(pvVar16);
    }
  }
  FUN_100238e0(param_1,&local_54,(byte *)"use_multi_dc");
  FUN_100184e0(param_1,&local_3c);
  uVar5 = FUN_10018200(&local_54,(int *)&local_3c);
  if (((char)uVar5 != '\0') && (pcVar6 = FUN_100182c0(&local_54), *pcVar6 == '\x03')) {
    pcVar6 = FUN_100182c0(&local_54);
    puVar8 = FUN_100142f0(pcVar6,(uint *)&local_44);
    local_14 = 8;
    local_94 = (undefined4 *)0x9;
    piVar9 = FUN_10021fc0(&DAT_1006b728,(int *)&local_94);
    FUN_1000ec10(piVar9,(int *)puVar8);
    local_14 = 0xffffffff;
    if (0xf < local_30) {
      pvVar16 = local_44;
      if ((0xfff < local_30 + 1) &&
         (pvVar16 = *(void **)((int)local_44 + -4),
         0x1f < (uint)((int)local_44 + (-4 - (int)pvVar16)))) goto LAB_1002183c;
      FUN_1002e346(pvVar16);
    }
  }
  FUN_100238e0(param_1,&local_6c,(byte *)"login");
  FUN_100184e0(param_1,&local_3c);
  uVar5 = FUN_10018200(&local_6c,(int *)&local_3c);
  if (((char)uVar5 != '\0') && (pcVar6 = FUN_100182c0(&local_6c), *pcVar6 == '\x01')) {
    pcVar6 = FUN_100182c0(&local_6c);
    local_54 = 0;
    puStack_50 = (undefined4 *)0x0;
    uStack_4c = 0;
    uStack_48 = 0;
    FUN_100184e0(pcVar6,&local_54);
    if (*extraout_ECX_00 == '\x01') {
      piVar9 = (int *)FUN_10023d80(*(void **)(extraout_ECX_00 + 8),&local_9c,&DAT_10060278);
      puStack_50 = (undefined4 *)*piVar9;
    }
    pcVar6 = FUN_100182c0(&local_6c);
    FUN_100184e0(pcVar6,&local_3c);
    uVar5 = FUN_10018200(&local_54,(int *)&local_3c);
    if (((char)uVar5 != '\0') && (pcVar6 = FUN_100182c0(&local_54), *pcVar6 == '\x03')) {
      pcVar6 = FUN_100182c0(&local_54);
      puVar8 = FUN_100142f0(pcVar6,(uint *)&local_44);
      local_14 = 9;
      local_94 = (undefined4 *)0xa;
      piVar9 = FUN_10021fc0(&DAT_1006b728,(int *)&local_94);
      FUN_1000ec10(piVar9,(int *)puVar8);
      local_14 = 0xffffffff;
      if (0xf < local_30) {
        pvVar16 = local_44;
        if ((0xfff < local_30 + 1) &&
           (pvVar16 = *(void **)((int)local_44 + -4),
           0x1f < (uint)((int)local_44 + (-4 - (int)pvVar16)))) goto LAB_10021841;
        FUN_1002e346(pvVar16);
      }
    }
    pcVar6 = FUN_100182c0(&local_6c);
    local_54 = 0;
    puStack_50 = (undefined4 *)0x0;
    uStack_4c = 0;
    uStack_48 = 0;
    FUN_100184e0(pcVar6,&local_54);
    if (*extraout_ECX_01 == '\x01') {
      piVar9 = (int *)FUN_10023d80(*(void **)(extraout_ECX_01 + 8),&local_9c,&DAT_10060280);
      puStack_50 = (undefined4 *)*piVar9;
    }
    pcVar6 = FUN_100182c0(&local_6c);
    FUN_100184e0(pcVar6,&local_3c);
    uVar5 = FUN_10018200(&local_54,(int *)&local_3c);
    if (((char)uVar5 != '\0') && (pcVar6 = FUN_100182c0(&local_54), *pcVar6 == '\x03')) {
      pcVar6 = FUN_100182c0(&local_54);
      puVar8 = FUN_100142f0(pcVar6,(uint *)&local_44);
      local_14 = 10;
      local_94 = (undefined4 *)0xb;
      piVar9 = FUN_10021fc0(&DAT_1006b728,(int *)&local_94);
      FUN_1000ec10(piVar9,(int *)puVar8);
      local_14 = 0xffffffff;
      if (0xf < local_30) {
        pvVar16 = local_44;
        if ((0xfff < local_30 + 1) &&
           (pvVar16 = *(void **)((int)local_44 + -4),
           0x1f < (uint)((int)local_44 + (-4 - (int)pvVar16)))) goto LAB_10021846;
        FUN_1002e346(pvVar16);
      }
    }
    pcVar6 = FUN_100182c0(&local_6c);
    FUN_100238e0(pcVar6,&local_54,(byte *)"redirect");
    pcVar6 = FUN_100182c0(&local_6c);
    FUN_100184e0(pcVar6,&local_3c);
    uVar5 = FUN_10018200(&local_54,(int *)&local_3c);
    if (((char)uVar5 != '\0') && (pcVar6 = FUN_100182c0(&local_54), *pcVar6 == '\x03')) {
      pcVar6 = FUN_100182c0(&local_54);
      puVar8 = FUN_100142f0(pcVar6,(uint *)&local_44);
      local_14 = 0xb;
      local_94 = (undefined4 *)0xc;
      piVar9 = FUN_10021fc0(&DAT_1006b728,(int *)&local_94);
      FUN_1000ec10(piVar9,(int *)puVar8);
      local_14 = 0xffffffff;
      if (0xf < local_30) {
        pvVar16 = local_44;
        if ((0xfff < local_30 + 1) &&
           (pvVar16 = *(void **)((int)local_44 + -4),
           0x1f < (uint)((int)local_44 + (-4 - (int)pvVar16)))) goto LAB_1002184b;
        FUN_1002e346(pvVar16);
      }
    }
    pcVar6 = FUN_100182c0(&local_6c);
    FUN_100239b0(pcVar6,&local_54);
    pcVar6 = FUN_100182c0(&local_6c);
    FUN_100184e0(pcVar6,&local_3c);
    uVar5 = FUN_10018200(&local_54,(int *)&local_3c);
    if (((char)uVar5 != '\0') && (pcVar6 = FUN_100182c0(&local_54), *pcVar6 == '\x03')) {
      pcVar6 = FUN_100182c0(&local_54);
      puVar8 = FUN_100142f0(pcVar6,(uint *)&local_44);
      local_14 = 0xc;
      local_94 = (undefined4 *)0xd;
      piVar9 = FUN_10021fc0(&DAT_1006b728,(int *)&local_94);
      FUN_1000ec10(piVar9,(int *)puVar8);
      local_14 = 0xffffffff;
      if (0xf < local_30) {
        pvVar16 = local_44;
        if ((0xfff < local_30 + 1) &&
           (pvVar16 = *(void **)((int)local_44 + -4),
           0x1f < (uint)((int)local_44 + (-4 - (int)pvVar16)))) goto LAB_10021850;
        FUN_1002e346(pvVar16);
      }
    }
    pcVar6 = FUN_100182c0(&local_6c);
    FUN_100238e0(pcVar6,&local_54,(byte *)"redirect_id");
    pcVar6 = FUN_100182c0(&local_6c);
    FUN_100184e0(pcVar6,&local_3c);
    uVar5 = FUN_10018200(&local_54,(int *)&local_3c);
    if (((char)uVar5 != '\0') && (pcVar6 = FUN_100182c0(&local_54), *pcVar6 == '\x03')) {
      pcVar6 = FUN_100182c0(&local_54);
      puVar8 = FUN_100142f0(pcVar6,(uint *)&local_44);
      local_14 = 0xd;
      local_94 = (undefined4 *)0xe;
      piVar9 = FUN_10021fc0(&DAT_1006b728,(int *)&local_94);
      FUN_1000ec10(piVar9,(int *)puVar8);
      local_14 = 0xffffffff;
      if (0xf < local_30) {
        pvVar16 = local_44;
        if ((0xfff < local_30 + 1) &&
           (pvVar16 = *(void **)((int)local_44 + -4),
           0x1f < (uint)((int)local_44 + (-4 - (int)pvVar16)))) goto LAB_10021855;
        FUN_1002e346(pvVar16);
      }
    }
    pcVar6 = FUN_100182c0(&local_6c);
    FUN_100238e0(pcVar6,&local_54,(byte *)"signup_url");
    pcVar6 = FUN_100182c0(&local_6c);
    FUN_100184e0(pcVar6,&local_3c);
    uVar5 = FUN_10018200(&local_54,(int *)&local_3c);
    if (((char)uVar5 != '\0') && (pcVar6 = FUN_100182c0(&local_54), *pcVar6 == '\x03')) {
      pcVar6 = FUN_100182c0(&local_54);
      puVar8 = FUN_100142f0(pcVar6,(uint *)&local_44);
      local_14 = 0xe;
      local_94 = (undefined4 *)0xf;
      piVar9 = FUN_10021fc0(&DAT_1006b728,(int *)&local_94);
      FUN_1000ec10(piVar9,(int *)puVar8);
      local_14 = 0xffffffff;
      if (0xf < local_30) {
        pvVar16 = local_44;
        if ((0xfff < local_30 + 1) &&
           (pvVar16 = *(void **)((int)local_44 + -4),
           0x1f < (uint)((int)local_44 + (-4 - (int)pvVar16)))) goto LAB_1002185a;
        FUN_1002e346(pvVar16);
      }
    }
    pcVar6 = FUN_100182c0(&local_6c);
    FUN_100238e0(pcVar6,&local_54,(byte *)"redeem_url");
    pcVar6 = FUN_100182c0(&local_6c);
    FUN_100184e0(pcVar6,&local_3c);
    uVar5 = FUN_10018200(&local_54,(int *)&local_3c);
    if (((char)uVar5 != '\0') && (pcVar6 = FUN_100182c0(&local_54), *pcVar6 == '\x03')) {
      pcVar6 = FUN_100182c0(&local_54);
      puVar8 = FUN_100142f0(pcVar6,(uint *)&local_44);
      local_14 = 0xf;
      local_94 = (undefined4 *)0x10;
      piVar9 = FUN_10021fc0(&DAT_1006b728,(int *)&local_94);
      FUN_1000ec10(piVar9,(int *)puVar8);
      local_14 = 0xffffffff;
      if (0xf < local_30) {
        pvVar16 = local_44;
        if ((0xfff < local_30 + 1) &&
           (pvVar16 = *(void **)((int)local_44 + -4),
           0x1f < (uint)((int)local_44 + (-4 - (int)pvVar16)))) goto LAB_1002185f;
        FUN_1002e346(pvVar16);
      }
    }
    pcVar6 = FUN_100182c0(&local_6c);
    FUN_100238e0(pcVar6,&local_54,(byte *)"use_redeem");
    pcVar6 = FUN_100182c0(&local_6c);
    FUN_100184e0(pcVar6,&local_3c);
    uVar5 = FUN_10018200(&local_54,(int *)&local_3c);
    if (((char)uVar5 != '\0') && (pcVar6 = FUN_100182c0(&local_54), *pcVar6 == '\x03')) {
      pcVar6 = FUN_100182c0(&local_54);
      puVar8 = FUN_100142f0(pcVar6,(uint *)&local_44);
      local_14 = 0x10;
      local_94 = (undefined4 *)0x11;
      piVar9 = FUN_10021fc0(&DAT_1006b728,(int *)&local_94);
      FUN_1000ec10(piVar9,(int *)puVar8);
      local_14 = 0xffffffff;
      if (0xf < local_30) {
        pvVar16 = local_44;
        if ((0xfff < local_30 + 1) &&
           (pvVar16 = *(void **)((int)local_44 + -4),
           0x1f < (uint)((int)local_44 + (-4 - (int)pvVar16)))) goto LAB_10021864;
        FUN_1002e346(pvVar16);
      }
    }
    pcVar6 = FUN_100182c0(&local_6c);
    local_54 = 0;
    puStack_50 = (undefined4 *)0x0;
    uStack_4c = 0;
    uStack_48 = 0;
    FUN_100184e0(pcVar6,&local_54);
    if (*extraout_ECX_02 == '\x01') {
      local_94 = (undefined4 *)**(int **)(extraout_ECX_02 + 8);
      cVar1 = *(char *)((int)local_94[1] + 0xd);
      puVar7 = local_94;
      puVar21 = (undefined4 *)local_94[1];
      while (cVar1 == '\0') {
        pbVar15 = (byte *)(puVar21 + 4);
        if (0xf < (uint)puVar21[9]) {
          pbVar15 = *(byte **)pbVar15;
        }
        uVar10 = FUN_100148a0(pbVar15,puVar21[8],(byte *)"auth_type",9);
        if ((int)uVar10 < 0) {
          puVar20 = (undefined4 *)puVar21[2];
          puVar21 = puVar7;
        }
        else {
          puVar20 = (undefined4 *)*puVar21;
        }
        puVar7 = puVar21;
        puVar21 = puVar20;
        cVar1 = *(char *)((int)puVar20 + 0xd);
      }
      if (*(char *)((int)puVar7 + 0xd) == '\0') {
        pbVar15 = (byte *)(puVar7 + 4);
        if (0xf < (uint)puVar7[9]) {
          pbVar15 = *(byte **)pbVar15;
        }
        uVar10 = FUN_100148a0(pbVar15,puVar7[8],(byte *)"auth_type",9);
        param_1 = local_98;
        puStack_50 = puVar7;
        if ((int)uVar10 < 1) goto LAB_10020746;
      }
      param_1 = local_98;
      puStack_50 = local_94;
    }
LAB_10020746:
    pcVar6 = FUN_100182c0(&local_6c);
    FUN_100184e0(pcVar6,&local_3c);
    uVar5 = FUN_10018200(&local_54,(int *)&local_3c);
    if (((char)uVar5 != '\0') && (pcVar6 = FUN_100182c0(&local_54), *pcVar6 == '\x03')) {
      pcVar6 = FUN_100182c0(&local_54);
      puVar8 = FUN_100142f0(pcVar6,(uint *)&local_44);
      local_14 = 0x11;
      local_94 = (undefined4 *)0x12;
      piVar9 = FUN_10021fc0(&DAT_1006b728,(int *)&local_94);
      FUN_1000ec10(piVar9,(int *)puVar8);
      local_14 = 0xffffffff;
      if (0xf < local_30) {
        pvVar16 = local_44;
        if ((0xfff < local_30 + 1) &&
           (pvVar16 = *(void **)((int)local_44 + -4),
           0x1f < (uint)((int)local_44 + (-4 - (int)pvVar16)))) goto LAB_10021869;
        FUN_1002e346(pvVar16);
      }
    }
    pcVar6 = FUN_100182c0(&local_6c);
    FUN_100238e0(pcVar6,&local_54,(byte *)"url_params");
    pcVar6 = FUN_100182c0(&local_6c);
    FUN_100184e0(pcVar6,&local_3c);
    uVar5 = FUN_10018200(&local_54,(int *)&local_3c);
    if (((char)uVar5 != '\0') && (pcVar6 = FUN_100182c0(&local_54), *pcVar6 == '\x01')) {
      local_14 = 0x12;
      pcVar6 = FUN_100182c0(&local_54);
      piVar9 = (int *)FUN_10021b60(pcVar6,&local_44);
      local_14._0_1_ = 0x13;
      local_94 = (undefined4 *)0x13;
      piVar11 = FUN_10021fc0(&DAT_1006b728,(int *)&local_94);
      FUN_1000ec10(piVar11,piVar9);
      local_14 = CONCAT31(local_14._1_3_,0x12);
      if (local_30 < 0x10) {
LAB_100208c0:
        local_14 = 0xffffffff;
        FUN_100208e2();
        return;
      }
      pvVar16 = local_44;
      if ((local_30 + 1 < 0x1000) ||
         (pvVar16 = *(void **)((int)local_44 + -4),
         (uint)((int)local_44 + (-4 - (int)pvVar16)) < 0x20)) {
        FUN_1002e346(pvVar16);
        goto LAB_100208c0;
      }
      goto LAB_1002186e;
    }
    pcVar6 = FUN_100182c0(&local_6c);
    local_54 = 0;
    puStack_50 = (undefined4 *)0x0;
    uStack_4c = 0;
    uStack_48 = 0;
    FUN_100184e0(pcVar6,&local_54);
    if (*extraout_ECX_03 == '\x01') {
      local_94 = (undefined4 *)**(undefined4 **)(extraout_ECX_03 + 8);
      cVar1 = *(char *)((int)local_94[1] + 0xd);
      puVar7 = local_94;
      puVar21 = (undefined4 *)local_94[1];
      while (cVar1 == '\0') {
        pbVar15 = (byte *)(puVar21 + 4);
        if (0xf < (uint)puVar21[9]) {
          pbVar15 = *(byte **)pbVar15;
        }
        uVar10 = FUN_100148a0(pbVar15,puVar21[8],(byte *)"protocol_handler",0x10);
        if ((int)uVar10 < 0) {
          puVar20 = (undefined4 *)puVar21[2];
          puVar21 = puVar7;
        }
        else {
          puVar20 = (undefined4 *)*puVar21;
        }
        puVar7 = puVar21;
        puVar21 = puVar20;
        cVar1 = *(char *)((int)puVar20 + 0xd);
      }
      if (*(char *)((int)puVar7 + 0xd) == '\0') {
        pbVar15 = (byte *)(puVar7 + 4);
        if (0xf < (uint)puVar7[9]) {
          pbVar15 = *(byte **)pbVar15;
        }
        uVar10 = FUN_100148a0(pbVar15,puVar7[8],(byte *)"protocol_handler",0x10);
        param_1 = local_98;
        puStack_50 = puVar7;
        if ((int)uVar10 < 1) goto LAB_10020986;
      }
      param_1 = local_98;
      puStack_50 = local_94;
    }
LAB_10020986:
    pcVar6 = FUN_100182c0(&local_6c);
    FUN_100184e0(pcVar6,&local_3c);
    uVar5 = FUN_10018200(&local_54,(int *)&local_3c);
    if (((char)uVar5 == '\0') || (pcVar6 = FUN_100182c0(&local_54), *pcVar6 != '\x01'))
    goto LAB_1002101a;
    pcVar6 = FUN_100182c0(&local_54);
    local_6c = 0;
    uStack_68 = 0;
    uStack_64 = 0;
    uStack_60 = 0;
    FUN_100184e0(pcVar6,&local_6c);
    if (*extraout_ECX_04 == '\x01') {
      puVar7 = (undefined4 *)FUN_10023d80(*(void **)(extraout_ECX_04 + 8),&local_9c,&DAT_1005fdb0);
      uStack_68 = *puVar7;
    }
    pcVar6 = FUN_100182c0(&local_54);
    FUN_100184e0(pcVar6,&local_3c);
    uVar5 = FUN_10018200(&local_6c,(int *)&local_3c);
    if (((char)uVar5 != '\0') && (pcVar6 = FUN_100182c0(&local_6c), *pcVar6 == '\x03')) {
      pcVar6 = FUN_100182c0(&local_6c);
      puVar8 = FUN_100142f0(pcVar6,(uint *)&local_44);
      local_14 = 0x15;
      local_94 = (undefined4 *)0x19;
      piVar9 = FUN_10021fc0(&DAT_1006b728,(int *)&local_94);
      FUN_1000ec10(piVar9,(int *)puVar8);
      local_14 = 0xffffffff;
      if (0xf < local_30) {
        pvVar16 = local_44;
        if ((0xfff < local_30 + 1) &&
           (pvVar16 = *(void **)((int)local_44 + -4),
           0x1f < (uint)((int)local_44 + (-4 - (int)pvVar16)))) goto LAB_10021873;
        FUN_1002e346(pvVar16);
      }
    }
    pcVar6 = FUN_100182c0(&local_54);
    FUN_100238e0(pcVar6,&local_6c,(byte *)"description");
    pcVar6 = FUN_100182c0(&local_54);
    FUN_100184e0(pcVar6,&local_3c);
    uVar5 = FUN_10018200(&local_6c,(int *)&local_3c);
    if (((char)uVar5 != '\0') && (pcVar6 = FUN_100182c0(&local_6c), *pcVar6 == '\x03')) {
      pcVar6 = FUN_100182c0(&local_6c);
      puVar8 = FUN_100142f0(pcVar6,(uint *)&local_44);
      local_14 = 0x16;
      local_94 = (undefined4 *)0x1a;
      piVar9 = FUN_10021fc0(&DAT_1006b728,(int *)&local_94);
      FUN_1000ec10(piVar9,(int *)puVar8);
      local_14 = 0xffffffff;
      if (0xf < local_30) {
        pvVar16 = local_44;
        if ((0xfff < local_30 + 1) &&
           (pvVar16 = *(void **)((int)local_44 + -4),
           0x1f < (uint)((int)local_44 + (-4 - (int)pvVar16)))) goto LAB_10021878;
        FUN_1002e346(pvVar16);
      }
    }
    pcVar6 = FUN_100182c0(&local_54);
    FUN_100238e0(pcVar6,&local_6c,(byte *)"handler");
    pcVar6 = FUN_100182c0(&local_54);
    FUN_100184e0(pcVar6,&local_3c);
    uVar5 = FUN_10018200(&local_6c,(int *)&local_3c);
    if (((char)uVar5 != '\0') && (pcVar6 = FUN_100182c0(&local_6c), *pcVar6 == '\x03')) {
      pcVar6 = FUN_100182c0(&local_6c);
      puVar8 = FUN_100142f0(pcVar6,(uint *)&local_44);
      local_14 = 0x17;
      local_94 = (undefined4 *)0x1b;
      piVar9 = FUN_10021fc0(&DAT_1006b728,(int *)&local_94);
      FUN_1000ec10(piVar9,(int *)puVar8);
      local_14 = 0xffffffff;
      if (0xf < local_30) {
        pvVar16 = local_44;
        if ((0xfff < local_30 + 1) &&
           (pvVar16 = *(void **)((int)local_44 + -4),
           0x1f < (uint)((int)local_44 + (-4 - (int)pvVar16)))) goto LAB_1002187d;
        FUN_1002e346(pvVar16);
      }
    }
    pcVar6 = FUN_100182c0(&local_54);
    local_6c = 0;
    uStack_68 = 0;
    uStack_64 = 0;
    uStack_60 = 0;
    FUN_100184e0(pcVar6,&local_6c);
    if (*extraout_ECX_05 == '\x01') {
      puVar7 = (undefined4 *)FUN_10023d80(*(void **)(extraout_ECX_05 + 8),&local_9c,&DAT_10060280);
      uStack_68 = *puVar7;
    }
    pcVar6 = FUN_100182c0(&local_54);
    FUN_100184e0(pcVar6,&local_3c);
    uVar5 = FUN_10018200(&local_6c,(int *)&local_3c);
    if (((char)uVar5 != '\0') && (pcVar6 = FUN_100182c0(&local_6c), *pcVar6 == '\x03')) {
      pcVar6 = FUN_100182c0(&local_6c);
      puVar8 = FUN_100142f0(pcVar6,(uint *)&local_44);
      local_14 = 0x18;
      local_94 = (undefined4 *)0x1c;
      piVar9 = FUN_10021fc0(&DAT_1006b728,(int *)&local_94);
      FUN_1000ec10(piVar9,(int *)puVar8);
      local_14 = 0xffffffff;
      if (0xf < local_30) {
        pvVar16 = local_44;
        if ((0xfff < local_30 + 1) &&
           (pvVar16 = *(void **)((int)local_44 + -4),
           0x1f < (uint)((int)local_44 + (-4 - (int)pvVar16)))) goto LAB_10021882;
        FUN_1002e346(pvVar16);
      }
    }
    pcVar6 = FUN_100182c0(&local_54);
    FUN_100238e0(pcVar6,&local_6c,(byte *)"redirect");
    pcVar6 = FUN_100182c0(&local_54);
    FUN_100184e0(pcVar6,&local_3c);
    uVar5 = FUN_10018200(&local_6c,(int *)&local_3c);
    if (((char)uVar5 != '\0') && (pcVar6 = FUN_100182c0(&local_6c), *pcVar6 == '\x03')) {
      pcVar6 = FUN_100182c0(&local_6c);
      puVar8 = FUN_100142f0(pcVar6,(uint *)&local_44);
      local_14 = 0x19;
      local_94 = (undefined4 *)0x1d;
      piVar9 = FUN_10021fc0(&DAT_1006b728,(int *)&local_94);
      FUN_1000ec10(piVar9,(int *)puVar8);
      local_14 = 0xffffffff;
      if (0xf < local_30) {
        pvVar16 = local_44;
        if ((0xfff < local_30 + 1) &&
           (pvVar16 = *(void **)((int)local_44 + -4),
           0x1f < (uint)((int)local_44 + (-4 - (int)pvVar16)))) goto LAB_10021887;
        FUN_1002e346(pvVar16);
      }
    }
    pcVar6 = FUN_100182c0(&local_54);
    FUN_100239b0(pcVar6,&local_6c);
    pcVar6 = FUN_100182c0(&local_54);
    FUN_100184e0(pcVar6,&local_3c);
    uVar5 = FUN_10018200(&local_6c,(int *)&local_3c);
    if (((char)uVar5 != '\0') && (pcVar6 = FUN_100182c0(&local_6c), *pcVar6 == '\x03')) {
      pcVar6 = FUN_100182c0(&local_6c);
      puVar8 = FUN_100142f0(pcVar6,(uint *)&local_44);
      local_14 = 0x1a;
      local_94 = (undefined4 *)0x1e;
      piVar9 = FUN_10021fc0(&DAT_1006b728,(int *)&local_94);
      FUN_1000ec10(piVar9,(int *)puVar8);
      local_14 = 0xffffffff;
      if (0xf < local_30) {
        pvVar16 = local_44;
        if ((0xfff < local_30 + 1) &&
           (pvVar16 = *(void **)((int)local_44 + -4),
           0x1f < (uint)((int)local_44 + (-4 - (int)pvVar16)))) goto LAB_1002188c;
        FUN_1002e346(pvVar16);
      }
    }
    pcVar6 = FUN_100182c0(&local_54);
    FUN_100238e0(pcVar6,&local_6c,(byte *)"redirect_id");
    pcVar6 = FUN_100182c0(&local_54);
    FUN_100184e0(pcVar6,&local_3c);
    uVar5 = FUN_10018200(&local_6c,(int *)&local_3c);
    if (((char)uVar5 != '\0') && (pcVar6 = FUN_100182c0(&local_6c), *pcVar6 == '\x03')) {
      pcVar6 = FUN_100182c0(&local_6c);
      puVar8 = FUN_100142f0(pcVar6,(uint *)&local_44);
      local_14 = 0x1b;
      local_94 = (undefined4 *)0x1f;
      piVar9 = FUN_10021fc0(&DAT_1006b728,(int *)&local_94);
      FUN_1000ec10(piVar9,(int *)puVar8);
      local_14 = 0xffffffff;
      if (0xf < local_30) {
        pvVar16 = local_44;
        if ((0xfff < local_30 + 1) &&
           (pvVar16 = *(void **)((int)local_44 + -4),
           0x1f < (uint)((int)local_44 + (-4 - (int)pvVar16)))) goto LAB_10021891;
        FUN_1002e346(pvVar16);
      }
    }
    pcVar6 = FUN_100182c0(&local_54);
    FUN_100238e0(pcVar6,&local_6c,(byte *)"signup_url");
    pcVar6 = FUN_100182c0(&local_54);
    FUN_100184e0(pcVar6,&local_3c);
    uVar5 = FUN_10018200(&local_6c,(int *)&local_3c);
    if (((char)uVar5 != '\0') && (pcVar6 = FUN_100182c0(&local_6c), *pcVar6 == '\x03')) {
      pcVar6 = FUN_100182c0(&local_6c);
      puVar8 = FUN_100142f0(pcVar6,(uint *)&local_44);
      local_14 = 0x1c;
      local_94 = (undefined4 *)0x20;
      piVar9 = FUN_10021fc0(&DAT_1006b728,(int *)&local_94);
      FUN_1000ec10(piVar9,(int *)puVar8);
      local_14 = 0xffffffff;
      if (0xf < local_30) {
        pvVar16 = local_44;
        if ((0xfff < local_30 + 1) &&
           (pvVar16 = *(void **)((int)local_44 + -4),
           0x1f < (uint)((int)local_44 + (-4 - (int)pvVar16)))) goto LAB_10021896;
        FUN_1002e346(pvVar16);
      }
    }
  }
LAB_1002101a:
  local_54 = 0;
  puStack_50 = (undefined4 *)0x0;
  uStack_4c = 0;
  uStack_48 = 0;
  FUN_100184e0(param_1,&local_54);
  if (*param_1 == '\x01') {
    local_94 = (undefined4 *)**(undefined4 **)(param_1 + 8);
    cVar1 = *(char *)((int)local_94[1] + 0xd);
    puVar7 = local_94;
    puVar21 = (undefined4 *)local_94[1];
    while (cVar1 == '\0') {
      pbVar15 = (byte *)(puVar21 + 4);
      if (0xf < (uint)puVar21[9]) {
        pbVar15 = *(byte **)pbVar15;
      }
      uVar10 = FUN_100148a0(pbVar15,puVar21[8],&DAT_10060304,2);
      if ((int)uVar10 < 0) {
        puVar20 = (undefined4 *)puVar21[2];
        puVar21 = puVar7;
      }
      else {
        puVar20 = (undefined4 *)*puVar21;
      }
      puVar7 = puVar21;
      puVar21 = puVar20;
      cVar1 = *(char *)((int)puVar20 + 0xd);
    }
    if (*(char *)((int)puVar7 + 0xd) == '\0') {
      pbVar15 = (byte *)(puVar7 + 4);
      if (0xf < (uint)puVar7[9]) {
        pbVar15 = *(byte **)pbVar15;
      }
      uVar10 = FUN_100148a0(pbVar15,puVar7[8],&DAT_10060304,2);
      param_1 = local_98;
      puStack_50 = puVar7;
      if ((int)uVar10 < 1) goto LAB_100210b6;
    }
    param_1 = local_98;
    puStack_50 = local_94;
  }
LAB_100210b6:
  FUN_100184e0(param_1,&local_3c);
  uVar5 = FUN_10018200(&local_54,(int *)&local_3c);
  if (((char)uVar5 != '\0') && (pcVar6 = FUN_100182c0(&local_54), *pcVar6 == '\x01')) {
    pcVar6 = FUN_100182c0(&local_54);
    FUN_100238e0(pcVar6,&local_6c,(byte *)"about_reg_path");
    pcVar6 = FUN_100182c0(&local_54);
    FUN_100184e0(pcVar6,&local_3c);
    uVar5 = FUN_10018200(&local_6c,(int *)&local_3c);
    if (((char)uVar5 != '\0') && (pcVar6 = FUN_100182c0(&local_6c), *pcVar6 == '\x03')) {
      pcVar6 = FUN_100182c0(&local_6c);
      puVar8 = FUN_100142f0(pcVar6,(uint *)&local_44);
      local_14 = 0x1d;
      local_94 = (undefined4 *)0x22;
      piVar9 = FUN_10021fc0(&DAT_1006b728,(int *)&local_94);
      FUN_1000ec10(piVar9,(int *)puVar8);
      local_14 = 0xffffffff;
      if (0xf < local_30) {
        pvVar16 = local_44;
        if ((0xfff < local_30 + 1) &&
           (pvVar16 = *(void **)((int)local_44 + -4),
           0x1f < (uint)((int)local_44 + (-4 - (int)pvVar16)))) goto LAB_1002189b;
        FUN_1002e346(pvVar16);
      }
    }
    pcVar6 = FUN_100182c0(&local_54);
    local_6c = 0;
    uStack_68 = 0;
    uStack_64 = 0;
    uStack_60 = 0;
    FUN_100184e0(pcVar6,&local_6c);
    if (*extraout_ECX_06 == '\x01') {
      puVar7 = (undefined4 *)FUN_10023d80(*(void **)(extraout_ECX_06 + 8),&local_9c,&DAT_10060318);
      uStack_68 = *puVar7;
    }
    pcVar6 = FUN_100182c0(&local_54);
    FUN_100184e0(pcVar6,&local_3c);
    uVar5 = FUN_10018200(&local_6c,(int *)&local_3c);
    if (((char)uVar5 != '\0') && (pcVar6 = FUN_100182c0(&local_6c), *pcVar6 == '\x01')) {
      pcVar6 = FUN_100182c0(&local_6c);
      FUN_100238e0(pcVar6,&local_3c,(byte *)"install_path");
      pcVar6 = FUN_100182c0(&local_6c);
      FUN_100184e0(pcVar6,&local_6c);
      uVar5 = FUN_10018200(&local_3c,&local_6c);
      if (((char)uVar5 != '\0') && (pcVar6 = FUN_100182c0(&local_3c), *pcVar6 == '\x03')) {
        pcVar6 = FUN_100182c0(&local_3c);
        puVar8 = FUN_100142f0(pcVar6,(uint *)apvStack_74);
        local_14 = 0x1e;
        local_94 = (undefined4 *)0x23;
        piVar9 = FUN_10021fc0(&DAT_1006b728,(int *)&local_94);
        FUN_1000ec10(piVar9,(int *)puVar8);
        local_14 = 0xffffffff;
        if (0xf < uStack_60) {
          pvVar16 = apvStack_74[0];
          if ((0xfff < uStack_60 + 1) &&
             (pvVar16 = *(void **)((int)apvStack_74[0] + -4),
             0x1f < (uint)((int)apvStack_74[0] + (-4 - (int)pvVar16)))) goto LAB_100218a0;
          FUN_1002e346(pvVar16);
        }
      }
    }
    pcVar6 = FUN_100182c0(&local_54);
    local_6c = 0;
    uStack_68 = 0;
    uStack_64 = 0;
    uStack_60 = 0;
    FUN_100184e0(pcVar6,&local_6c);
    if (*extraout_ECX_07 == '\x01') {
      puVar7 = (undefined4 *)FUN_10023d80(*(void **)(extraout_ECX_07 + 8),&local_9c,&DAT_1006032c);
      uStack_68 = *puVar7;
    }
    pcVar6 = FUN_100182c0(&local_54);
    FUN_100184e0(pcVar6,&local_3c);
    uVar5 = FUN_10018200(&local_6c,(int *)&local_3c);
    if (((char)uVar5 != '\0') && (pcVar6 = FUN_100182c0(&local_6c), *pcVar6 == '\x01')) {
      pcVar6 = FUN_100182c0(&local_6c);
      FUN_100238e0(pcVar6,&local_3c,(byte *)"install_path");
      pcVar6 = FUN_100182c0(&local_6c);
      FUN_100184e0(pcVar6,&local_54);
      uVar5 = FUN_10018200(&local_3c,&local_54);
      if (((char)uVar5 != '\0') && (pcVar6 = FUN_100182c0(&local_3c), *pcVar6 == '\x03')) {
        pcVar6 = FUN_100182c0(&local_3c);
        puVar8 = FUN_100142f0(pcVar6,(uint *)apvStack_5c);
        local_14 = 0x1f;
        local_94 = (undefined4 *)0x24;
        piVar9 = FUN_10021fc0(&DAT_1006b728,(int *)&local_94);
        FUN_1000ec10(piVar9,(int *)puVar8);
        local_14 = 0xffffffff;
        if (0xf < uStack_48) {
          pvVar16 = apvStack_5c[0];
          if ((0xfff < uStack_48 + 1) &&
             (pvVar16 = *(void **)((int)apvStack_5c[0] + -4),
             0x1f < (uint)((int)apvStack_5c[0] + (-4 - (int)pvVar16)))) goto LAB_100218a5;
          FUN_1002e346(pvVar16);
        }
      }
    }
  }
  FUN_100238e0(param_1,&local_54,(byte *)"bucket_testing");
  FUN_100184e0(param_1,&local_3c);
  uVar5 = FUN_10018200(&local_54,(int *)&local_3c);
  if (((char)uVar5 != '\0') && (pcVar6 = FUN_100182c0(&local_54), *pcVar6 == '\x01')) {
    pcVar6 = FUN_100182c0(&local_54);
    FUN_100238e0(pcVar6,&local_3c,(byte *)"app_id");
    pcVar6 = FUN_100182c0(&local_54);
    FUN_100184e0(pcVar6,&local_54);
    uVar5 = FUN_10018200(&local_3c,&local_54);
    if (((char)uVar5 != '\0') && (pcVar6 = FUN_100182c0(&local_3c), *pcVar6 == '\x03')) {
      pcVar6 = FUN_100182c0(&local_3c);
      puVar8 = FUN_100142f0(pcVar6,(uint *)apvStack_5c);
      local_14 = 0x20;
      local_94 = (undefined4 *)0x25;
      piVar9 = FUN_10021fc0(&DAT_1006b728,(int *)&local_94);
      FUN_1000ec10(piVar9,(int *)puVar8);
      local_14 = 0xffffffff;
      if (0xf < uStack_48) {
        pvVar16 = apvStack_5c[0];
        if ((0xfff < uStack_48 + 1) &&
           (pvVar16 = *(void **)((int)apvStack_5c[0] + -4),
           0x1f < (uint)((int)apvStack_5c[0] + (-4 - (int)pvVar16)))) goto LAB_100218aa;
        FUN_1002e346(pvVar16);
      }
    }
  }
  piVar9 = (int *)*DAT_1006b728;
  if (piVar9 != DAT_1006b728) {
    do {
      piVar11 = piVar9 + 5;
      if (0xf < (uint)piVar9[10]) {
        piVar11 = (int *)*piVar11;
      }
      FUN_1001c8a0(&local_44,(LPCSTR)piVar11,uVar4);
      ppvVar13 = &local_44;
      local_14 = 0x21;
      piVar11 = FUN_10022090(&DAT_1006b720,piVar9 + 4);
      FUN_10005380(piVar11,(int *)ppvVar13);
      local_14 = 0xffffffff;
      if (7 < local_30) {
        pvVar16 = local_44;
        if ((0xfff < local_30 * 2 + 2) &&
           (pvVar16 = *(void **)((int)local_44 + -4),
           0x1f < (uint)((int)local_44 + (-4 - (int)pvVar16)))) goto LAB_100218b4;
        FUN_1002e346(pvVar16);
      }
      piVar11 = (int *)piVar9[2];
      if (*(char *)((int)piVar11 + 0xd) == '\0') {
        cVar1 = *(char *)(*piVar11 + 0xd);
        piVar9 = piVar11;
        piVar11 = (int *)*piVar11;
        while (cVar1 == '\0') {
          cVar1 = *(char *)(*piVar11 + 0xd);
          piVar9 = piVar11;
          piVar11 = (int *)*piVar11;
        }
      }
      else {
        cVar1 = *(char *)(piVar9[1] + 0xd);
        piVar3 = (int *)piVar9[1];
        piVar11 = piVar9;
        while ((piVar9 = piVar3, cVar1 == '\0' && (piVar11 == (int *)piVar9[2]))) {
          cVar1 = *(char *)(piVar9[1] + 0xd);
          piVar3 = (int *)piVar9[1];
          piVar11 = piVar9;
        }
      }
    } while (piVar9 != DAT_1006b728);
  }
  local_94 = (undefined4 *)0x6;
  pWVar12 = (LPCWSTR)FUN_10022090(&DAT_1006b720,(int *)&local_94);
  if (7 < *(uint *)(pWVar12 + 10)) {
    pWVar12 = *(LPCWSTR *)pWVar12;
  }
  FUN_1001cec0(appppWStack_90,pWVar12);
  local_14 = 0x22;
  pppppWVar14 = appppWStack_90;
  if (7 < uStack_7c) {
    pppppWVar14 = (LPCWSTR ****)appppWStack_90[0];
  }
  FUN_1001c850(&local_44,(LPCWSTR)pppppWVar14);
  local_14 = CONCAT31(local_14._1_3_,0x23);
  local_98 = (char *)0x14;
  ppvVar13 = (void **)FUN_10021fc0(&DAT_1006b728,(int *)&local_98);
  if (ppvVar13 != &local_44) {
    if ((void *)0xf < ppvVar13[5]) {
      pvVar16 = *ppvVar13;
      pvVar17 = pvVar16;
      if ((0xfff < (int)ppvVar13[5] + 1U) &&
         (pvVar17 = *(void **)((int)pvVar16 + -4), 0x1f < (uint)((int)pvVar16 + (-4 - (int)pvVar17))
         )) goto LAB_100218af;
      FUN_1002e346(pvVar17);
    }
    pvVar16 = local_44;
    local_44 = (void *)((uint)local_44 & 0xffffff00);
    *ppvVar13 = pvVar16;
    ppvVar13[1] = pvStack_40;
    ppvVar13[2] = local_3c;
    ppvVar13[3] = pvStack_38;
    *(ulonglong *)(ppvVar13 + 4) = CONCAT44(local_30,uStack_34);
    local_30 = 0xf;
  }
  local_14 = CONCAT31(local_14._1_3_,0x22);
  if (0xf < local_30) {
    pvVar16 = local_44;
    if ((0xfff < local_30 + 1) &&
       (pvVar16 = *(void **)((int)local_44 + -4), 0x1f < (uint)((int)local_44 + (-4 - (int)pvVar16))
       )) goto LAB_100218af;
    FUN_1002e346(pvVar16);
  }
  puVar8 = (uint *)&DAT_100600c4;
  local_98 = (char *)0x15;
  if (iStack_78 != 0) {
    puVar8 = (uint *)&DAT_10060340;
  }
  piVar9 = FUN_10021fc0(&DAT_1006b728,(int *)&local_98);
  puVar19 = puVar8;
  do {
    uVar4 = *puVar19;
    puVar19 = (uint *)((int)puVar19 + 1);
  } while ((char)uVar4 != '\0');
  FUN_10008e70(piVar9,puVar8,(int)puVar19 - ((int)puVar8 + 1));
  local_98 = (char *)0x14;
  pppppWVar14 = (LPCWSTR ****)FUN_10022090(&DAT_1006b720,(int *)&local_98);
  if (pppppWVar14 != appppWStack_90) {
    pppppWVar18 = appppWStack_90;
    if (7 < uStack_7c) {
      pppppWVar18 = (LPCWSTR ****)appppWStack_90[0];
    }
    FUN_10001d40(pppppWVar14,(uint *)pppppWVar18,uStack_80);
  }
  puVar8 = (uint *)&DAT_10060344;
  local_9c = 0x15;
  if (iStack_78 != 0) {
    puVar8 = (uint *)&DAT_1006034c;
  }
  piVar9 = FUN_10022090(&DAT_1006b720,&local_9c);
  puVar19 = puVar8;
  do {
    uVar4 = *puVar19;
    puVar19 = (uint *)((int)puVar19 + 2);
  } while ((short)uVar4 != 0);
  FUN_10001d40(piVar9,puVar8,(int)puVar19 - ((int)puVar8 + 2) >> 1);
  if (7 < uStack_7c) {
    pppppWVar14 = (LPCWSTR ****)appppWStack_90[0];
    if ((0xfff < uStack_7c * 2 + 2) &&
       (pppppWVar14 = (LPCWSTR ****)appppWStack_90[0][-1],
       0x1f < (uint)((int)appppWStack_90[0] + (-4 - (int)pppppWVar14)))) goto LAB_100218b4;
    FUN_1002e346(pppppWVar14);
  }
  ExceptionList = local_1c;
  FUN_1002e315(local_2c ^ (uint)&stack0xfffffff0);
  return;
}


// FUNCTION_END

// FUNCTION_START: Catch@100208c9 @ 100208c9