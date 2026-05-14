void __fastcall FUN_10025ae0(char *param_1,void *param_2)

{
  char cVar1;
  uint uVar2;
  uint uVar3;
  undefined4 *puVar4;
  uint uVar5;
  undefined4 uVar6;
  char *pcVar7;
  uint *puVar8;
  uint *puVar9;
  void *pvVar10;
  byte *pbVar11;
  void *pvVar12;
  char *extraout_ECX;
  undefined4 *puVar13;
  ulonglong uVar14;
  uint local_19c [6];
  undefined1 local_184 [24];
  int local_16c [7];
  char *local_150;
  undefined4 *local_14c;
  undefined4 local_148;
  void *local_144 [2];
  int local_13c [3];
  uint local_130;
  int local_12c [3];
  undefined4 local_120 [4];
  undefined4 local_110 [4];
  undefined4 local_100 [4];
  undefined4 local_f0 [4];
  undefined4 local_e0 [4];
  undefined4 local_d0 [4];
  undefined4 local_c0 [4];
  undefined4 local_b0 [4];
  undefined4 local_a0 [4];
  undefined4 local_90 [4];
  uint local_80 [2];
  undefined8 local_78;
  undefined4 uStack_70;
  undefined4 uStack_6c;
  undefined4 local_64;
  undefined4 *puStack_60;
  undefined4 uStack_5c;
  undefined4 uStack_58;
  undefined4 local_54;
  undefined4 *puStack_50;
  undefined4 uStack_4c;
  undefined4 uStack_48;
  undefined4 local_44;
  undefined4 uStack_40;
  undefined4 uStack_3c;
  undefined4 uStack_38;
  undefined4 local_34;
  undefined4 uStack_30;
  undefined4 uStack_2c;
  undefined4 uStack_28;
  uint local_24;
  undefined1 *puStack_20;
  void *local_1c;
  undefined1 *puStack_18;
  undefined4 local_14;
  
  puStack_20 = &stack0xfffffffc;
  local_14 = 0xffffffff;
  puStack_18 = &LAB_1005024e;
  local_1c = ExceptionList;
  local_24 = DAT_10069054 ^ (uint)&stack0xfffffff0;
  ExceptionList = &local_1c;
  local_150 = param_1;
  FUN_100238e0(param_1,local_90,(byte *)"email");
  local_34 = 0;
  uStack_30 = 0;
  uStack_2c = 0;
  uStack_28 = 0;
  FUN_100184e0(param_1,&local_34);
  if (*param_1 == '\x01') {
    puVar4 = (undefined4 *)FUN_10023d80(*(void **)(param_1 + 8),(int *)&local_14c,&DAT_1005fdb0);
    uStack_30 = *puVar4;
  }
  FUN_100238e0(param_1,local_a0,(byte *)"country");
  FUN_100238e0(param_1,local_b0,(byte *)"fingerprint");
  FUN_100238e0(param_1,local_c0,(byte *)"device_name");
  FUN_100238e0(param_1,local_d0,(byte *)"sellerid");
  local_44 = 0;
  uStack_40 = 0;
  uStack_3c = 0;
  uStack_38 = 0;
  FUN_100184e0(param_1,&local_44);
  if (*param_1 == '\x01') {
    puVar4 = (undefined4 *)FUN_10023d80(*(void **)(param_1 + 8),(int *)&local_14c,&DAT_10060cc0);
    uStack_40 = *puVar4;
  }
  FUN_100238e0(param_1,local_e0,(byte *)"profile_id");
  local_54 = 0;
  puStack_50 = (undefined4 *)0x0;
  uStack_4c = 0;
  uStack_48 = 0;
  FUN_100184e0(param_1,&local_54);
  if (*param_1 == '\x01') {
    local_14c = (undefined4 *)**(int **)(param_1 + 8);
    cVar1 = *(char *)((int)local_14c[1] + 0xd);
    local_148 = local_14c;
    puVar4 = (undefined4 *)local_14c[1];
    while (cVar1 == '\0') {
      pbVar11 = (byte *)(puVar4 + 4);
      if (0xf < (uint)puVar4[9]) {
        pbVar11 = *(byte **)pbVar11;
      }
      uVar5 = FUN_100148a0(pbVar11,puVar4[8],(byte *)"profile_owner",0xd);
      if ((int)uVar5 < 0) {
        puVar13 = (undefined4 *)puVar4[2];
      }
      else {
        puVar13 = (undefined4 *)*puVar4;
        local_148 = puVar4;
      }
      puVar4 = puVar13;
      cVar1 = *(char *)((int)puVar13 + 0xd);
    }
    if (*(char *)((int)local_148 + 0xd) == '\0') {
      pbVar11 = (byte *)(local_148 + 4);
      if (0xf < (uint)local_148[9]) {
        pbVar11 = *(byte **)pbVar11;
      }
      uVar5 = FUN_100148a0(pbVar11,local_148[8],(byte *)"profile_owner",0xd);
      param_1 = local_150;
      puStack_50 = local_148;
      if ((int)uVar5 < 1) goto LAB_10025ca8;
    }
    param_1 = local_150;
    puStack_50 = local_14c;
  }
LAB_10025ca8:
  FUN_100238e0(param_1,local_f0,(byte *)"profile_type");
  FUN_100238e0(param_1,local_100,(byte *)"profile_name");
  FUN_100238e0(param_1,local_110,(byte *)"providerid");
  FUN_100238e0(param_1,local_120,(byte *)"traits");
  local_64 = 0;
  puStack_60 = (undefined4 *)0x0;
  uStack_5c = 0;
  uStack_58 = 0;
  FUN_100184e0(param_1,&local_64);
  if (*param_1 == '\x01') {
    local_14c = (undefined4 *)**(undefined4 **)(param_1 + 8);
    cVar1 = *(char *)((int)local_14c[1] + 0xd);
    local_148 = local_14c;
    puVar4 = (undefined4 *)local_14c[1];
    while (cVar1 == '\0') {
      pbVar11 = (byte *)(puVar4 + 4);
      if (0xf < (uint)puVar4[9]) {
        pbVar11 = *(byte **)pbVar11;
      }
      uVar5 = FUN_100148a0(pbVar11,puVar4[8],(byte *)"organization_level",0x12);
      if ((int)uVar5 < 0) {
        puVar13 = (undefined4 *)puVar4[2];
      }
      else {
        puVar13 = (undefined4 *)*puVar4;
        local_148 = puVar4;
      }
      puVar4 = puVar13;
      cVar1 = *(char *)((int)puVar13 + 0xd);
    }
    if (*(char *)((int)local_148 + 0xd) == '\0') {
      pbVar11 = (byte *)(local_148 + 4);
      if (0xf < (uint)local_148[9]) {
        pbVar11 = *(byte **)pbVar11;
      }
      uVar5 = FUN_100148a0(pbVar11,local_148[8],(byte *)"organization_level",0x12);
      param_1 = local_150;
      puStack_60 = local_148;
      if ((int)uVar5 < 1) goto LAB_10025da8;
    }
    param_1 = local_150;
    puStack_60 = local_14c;
  }
LAB_10025da8:
  FUN_100238e0(param_1,(undefined4 *)&local_78,(byte *)"created_ts");
  FUN_100184e0(param_1,local_13c);
  uVar6 = FUN_10018200(local_90,local_13c);
  if (((char)uVar6 == '\0') || (pcVar7 = FUN_100182c0(local_90), *pcVar7 != '\x03')) {
LAB_10025e3e:
    FUN_100184e0(param_1,local_13c);
    uVar6 = FUN_10018200(&local_34,local_13c);
    if (((char)uVar6 != '\0') && (pcVar7 = FUN_100182c0(&local_34), *pcVar7 == '\x03')) {
      pcVar7 = FUN_100182c0(&local_34);
      puVar8 = FUN_100142f0(pcVar7,(uint *)local_144);
      FUN_1000ec10((void *)((int)param_2 + 0x18),(int *)puVar8);
      if (local_130 < 0x10) goto LAB_10025ec5;
      pvVar12 = local_144[0];
      if ((local_130 + 1 < 0x1000) ||
         (pvVar12 = *(void **)((int)local_144[0] + -4),
         (uint)((int)local_144[0] + (-4 - (int)pvVar12)) < 0x20)) {
        FUN_1002e346(pvVar12);
        goto LAB_10025ec5;
      }
      goto LAB_100269d3;
    }
LAB_10025ec5:
    FUN_100184e0(param_1,local_13c);
    uVar6 = FUN_10018200(local_a0,local_13c);
    if (((char)uVar6 != '\0') && (pcVar7 = FUN_100182c0(local_a0), *pcVar7 == '\x03')) {
      pcVar7 = FUN_100182c0(local_a0);
      puVar8 = FUN_100142f0(pcVar7,(uint *)local_144);
      FUN_1000ec10((void *)((int)param_2 + 0x30),(int *)puVar8);
      if (local_130 < 0x10) goto LAB_10025f55;
      pvVar12 = local_144[0];
      if ((local_130 + 1 < 0x1000) ||
         (pvVar12 = *(void **)((int)local_144[0] + -4),
         (uint)((int)local_144[0] + (-4 - (int)pvVar12)) < 0x20)) {
        FUN_1002e346(pvVar12);
        goto LAB_10025f55;
      }
      goto LAB_100269d8;
    }
LAB_10025f55:
    FUN_100184e0(param_1,local_13c);
    uVar6 = FUN_10018200(local_b0,local_13c);
    if (((char)uVar6 != '\0') && (pcVar7 = FUN_100182c0(local_b0), *pcVar7 == '\x03')) {
      pcVar7 = FUN_100182c0(local_b0);
      puVar8 = FUN_100142f0(pcVar7,(uint *)local_144);
      FUN_1000ec10((void *)((int)param_2 + 0x48),(int *)puVar8);
      if (local_130 < 0x10) goto LAB_10025fe5;
      pvVar12 = local_144[0];
      if ((local_130 + 1 < 0x1000) ||
         (pvVar12 = *(void **)((int)local_144[0] + -4),
         (uint)((int)local_144[0] + (-4 - (int)pvVar12)) < 0x20)) {
        FUN_1002e346(pvVar12);
        goto LAB_10025fe5;
      }
      goto LAB_100269dd;
    }
LAB_10025fe5:
    FUN_100184e0(param_1,local_13c);
    uVar6 = FUN_10018200(local_c0,local_13c);
    if (((char)uVar6 != '\0') && (pcVar7 = FUN_100182c0(local_c0), *pcVar7 == '\x03')) {
      pcVar7 = FUN_100182c0(local_c0);
      puVar8 = FUN_100142f0(pcVar7,(uint *)local_144);
      FUN_1000ec10((void *)((int)param_2 + 0x60),(int *)puVar8);
      if (local_130 < 0x10) goto LAB_10026075;
      pvVar12 = local_144[0];
      if ((local_130 + 1 < 0x1000) ||
         (pvVar12 = *(void **)((int)local_144[0] + -4),
         (uint)((int)local_144[0] + (-4 - (int)pvVar12)) < 0x20)) {
        FUN_1002e346(pvVar12);
        goto LAB_10026075;
      }
      goto LAB_100269e2;
    }
LAB_10026075:
    FUN_100184e0(param_1,local_13c);
    uVar6 = FUN_10018200(local_d0,local_13c);
    if (((char)uVar6 != '\0') && (pcVar7 = FUN_100182c0(local_d0), *pcVar7 == '\x03')) {
      pcVar7 = FUN_100182c0(local_d0);
      puVar8 = FUN_100142f0(pcVar7,(uint *)local_144);
      FUN_1000ec10((void *)((int)param_2 + 0x78),(int *)puVar8);
      if (local_130 < 0x10) goto LAB_10026105;
      pvVar12 = local_144[0];
      if ((local_130 + 1 < 0x1000) ||
         (pvVar12 = *(void **)((int)local_144[0] + -4),
         (uint)((int)local_144[0] + (-4 - (int)pvVar12)) < 0x20)) {
        FUN_1002e346(pvVar12);
        goto LAB_10026105;
      }
      goto LAB_100269e7;
    }
LAB_10026105:
    FUN_100184e0(param_1,local_13c);
    uVar6 = FUN_10018200(&local_44,local_13c);
    if (((char)uVar6 == '\0') || (pcVar7 = FUN_100182c0(&local_44), *pcVar7 != '\x03')) {
LAB_1002618f:
      FUN_100184e0(param_1,local_13c);
      uVar6 = FUN_10018200(&local_54,local_13c);
      if (((char)uVar6 == '\0') || (pcVar7 = FUN_100182c0(&local_54), *pcVar7 != '\x04')) {
        *(undefined1 *)((int)param_2 + 0xa9) = 0;
      }
      else {
        pcVar7 = FUN_100182c0(&local_54);
        if (*pcVar7 != '\x04') goto LAB_100269f1;
        local_148 = (undefined4 *)CONCAT13(1,CONCAT12(pcVar7[8],(undefined2)local_148));
        *(undefined2 *)((int)param_2 + 0xa8) = local_148._2_2_;
      }
      FUN_100184e0(param_1,local_13c);
      uVar6 = FUN_10018200(local_e0,local_13c);
      if (((char)uVar6 != '\0') && (pcVar7 = FUN_100182c0(local_e0), *pcVar7 == '\x03')) {
        pcVar7 = FUN_100182c0(local_e0);
        puVar9 = FUN_100142f0(pcVar7,(uint *)local_144);
        puVar8 = (uint *)((int)param_2 + 0xac);
        if (*(char *)((int)param_2 + 0xc4) == '\0') {
          *puVar8 = 0;
          *(undefined4 *)((int)param_2 + 0xbc) = 0;
          *(undefined4 *)((int)param_2 + 0xc0) = 0;
          uVar5 = puVar9[1];
          uVar2 = puVar9[2];
          uVar3 = puVar9[3];
          *puVar8 = *puVar9;
          *(uint *)((int)param_2 + 0xb0) = uVar5;
          *(uint *)((int)param_2 + 0xb4) = uVar2;
          *(uint *)((int)param_2 + 0xb8) = uVar3;
          *(undefined8 *)((int)param_2 + 0xbc) = *(undefined8 *)(puVar9 + 4);
          puVar9[4] = 0;
          puVar9[5] = 0xf;
          *(undefined1 *)puVar9 = 0;
          *(undefined1 *)((int)param_2 + 0xc4) = 1;
        }
        else {
          FUN_1000ec10(puVar8,(int *)puVar9);
        }
        if (local_130 < 0x10) goto LAB_10026341;
        pvVar12 = local_144[0];
        if ((local_130 + 1 < 0x1000) ||
           (pvVar12 = *(void **)((int)local_144[0] + -4),
           (uint)((int)local_144[0] + (-4 - (int)pvVar12)) < 0x20)) {
          FUN_1002e346(pvVar12);
          goto LAB_10026341;
        }
        FUN_10032f7f();
LAB_10026a48:
        FUN_10032f7f();
LAB_10026a4d:
        FUN_10032f7f();
LAB_10026a52:
        FUN_10032f7f();
LAB_10026a57:
        FUN_10032f7f();
LAB_10026a5c:
        pcVar7 = (char *)FUN_10032f7f();
LAB_10026a61:
        puVar8 = (uint *)FUN_1000f7b0(pcVar7);
        puVar8 = FUN_10005690(local_184,puVar8);
        local_14 = 2;
        puVar8 = FUN_10005f20(local_19c,(uint *)"type must be number, but is ",puVar8);
        local_14 = CONCAT31(local_14._1_3_,3);
        FUN_1000ad90(local_16c,0x12e,puVar8);
                    /* WARNING: Subroutine does not return */
        __CxxThrowException_8(local_16c,&DAT_10067608);
      }
      if (*(char *)((int)param_2 + 0xc4) != '\0') {
        if (0xf < *(uint *)((int)param_2 + 0xc0)) {
          pvVar12 = *(void **)((int)param_2 + 0xac);
          pvVar10 = pvVar12;
          if ((0xfff < *(uint *)((int)param_2 + 0xc0) + 1) &&
             (pvVar10 = *(void **)((int)pvVar12 + -4),
             0x1f < (uint)((int)pvVar12 + (-4 - (int)pvVar10)))) goto LAB_100269ce;
          FUN_1002e346(pvVar10);
        }
        *(undefined4 *)((int)param_2 + 0xbc) = 0;
        *(undefined4 *)((int)param_2 + 0xc0) = 0xf;
        *(undefined1 *)((int)param_2 + 0xac) = 0;
        *(undefined1 *)((int)param_2 + 0xc4) = 0;
      }
LAB_10026341:
      FUN_100184e0(param_1,local_13c);
      uVar6 = FUN_10018200(local_f0,local_13c);
      if (((char)uVar6 == '\0') || (pcVar7 = FUN_100182c0(local_f0), *pcVar7 != '\x03')) {
        if (*(char *)((int)param_2 + 0xe0) != '\0') {
          if (0xf < *(uint *)((int)param_2 + 0xdc)) {
            pvVar12 = *(void **)((int)param_2 + 200);
            pvVar10 = pvVar12;
            if ((0xfff < *(uint *)((int)param_2 + 0xdc) + 1) &&
               (pvVar10 = *(void **)((int)pvVar12 + -4),
               0x1f < (uint)((int)pvVar12 + (-4 - (int)pvVar10)))) goto LAB_100269ce;
            FUN_1002e346(pvVar10);
          }
          *(undefined4 *)((int)param_2 + 0xd8) = 0;
          *(undefined4 *)((int)param_2 + 0xdc) = 0xf;
          *(undefined1 *)((int)param_2 + 200) = 0;
          *(undefined1 *)((int)param_2 + 0xe0) = 0;
        }
      }
      else {
        pcVar7 = FUN_100182c0(local_f0);
        puVar9 = FUN_100142f0(pcVar7,(uint *)local_144);
        puVar8 = (uint *)((int)param_2 + 200);
        if (*(char *)((int)param_2 + 0xe0) == '\0') {
          *puVar8 = 0;
          *(undefined4 *)((int)param_2 + 0xd8) = 0;
          *(undefined4 *)((int)param_2 + 0xdc) = 0;
          uVar5 = puVar9[1];
          uVar2 = puVar9[2];
          uVar3 = puVar9[3];
          *puVar8 = *puVar9;
          *(uint *)((int)param_2 + 0xcc) = uVar5;
          *(uint *)((int)param_2 + 0xd0) = uVar2;
          *(uint *)((int)param_2 + 0xd4) = uVar3;
          *(undefined8 *)((int)param_2 + 0xd8) = *(undefined8 *)(puVar9 + 4);
          puVar9[4] = 0;
          puVar9[5] = 0xf;
          *(undefined1 *)puVar9 = 0;
          *(undefined1 *)((int)param_2 + 0xe0) = 1;
        }
        else {
          FUN_1000ec10(puVar8,(int *)puVar9);
        }
        if (0xf < local_130) {
          pvVar12 = local_144[0];
          if ((0xfff < local_130 + 1) &&
             (pvVar12 = *(void **)((int)local_144[0] + -4),
             0x1f < (uint)((int)local_144[0] + (-4 - (int)pvVar12)))) goto LAB_10026a48;
          FUN_1002e346(pvVar12);
        }
      }
      FUN_100184e0(param_1,local_13c);
      uVar6 = FUN_10018200(local_100,local_13c);
      if (((char)uVar6 == '\0') || (pcVar7 = FUN_100182c0(local_100), *pcVar7 != '\x03')) {
        if (*(char *)((int)param_2 + 0xfc) != '\0') {
          if (0xf < *(uint *)((int)param_2 + 0xf8)) {
            pvVar12 = *(void **)((int)param_2 + 0xe4);
            pvVar10 = pvVar12;
            if ((0xfff < *(uint *)((int)param_2 + 0xf8) + 1) &&
               (pvVar10 = *(void **)((int)pvVar12 + -4),
               0x1f < (uint)((int)pvVar12 + (-4 - (int)pvVar10)))) goto LAB_100269ce;
            FUN_1002e346(pvVar10);
          }
          *(undefined4 *)((int)param_2 + 0xf4) = 0;
          *(undefined4 *)((int)param_2 + 0xf8) = 0xf;
          *(undefined1 *)((int)param_2 + 0xe4) = 0;
          *(undefined1 *)((int)param_2 + 0xfc) = 0;
        }
      }
      else {
        pcVar7 = FUN_100182c0(local_100);
        puVar9 = FUN_100142f0(pcVar7,(uint *)local_144);
        puVar8 = (uint *)((int)param_2 + 0xe4);
        if (*(char *)((int)param_2 + 0xfc) == '\0') {
          *puVar8 = 0;
          *(undefined4 *)((int)param_2 + 0xf4) = 0;
          *(undefined4 *)((int)param_2 + 0xf8) = 0;
          uVar5 = puVar9[1];
          uVar2 = puVar9[2];
          uVar3 = puVar9[3];
          *puVar8 = *puVar9;
          *(uint *)((int)param_2 + 0xe8) = uVar5;
          *(uint *)((int)param_2 + 0xec) = uVar2;
          *(uint *)((int)param_2 + 0xf0) = uVar3;
          *(undefined8 *)((int)param_2 + 0xf4) = *(undefined8 *)(puVar9 + 4);
          puVar9[4] = 0;
          puVar9[5] = 0xf;
          *(undefined1 *)puVar9 = 0;
          *(undefined1 *)((int)param_2 + 0xfc) = 1;
        }
        else {
          FUN_1000ec10(puVar8,(int *)puVar9);
        }
        if (0xf < local_130) {
          pvVar12 = local_144[0];
          if ((0xfff < local_130 + 1) &&
             (pvVar12 = *(void **)((int)local_144[0] + -4),
             0x1f < (uint)((int)local_144[0] + (-4 - (int)pvVar12)))) goto LAB_10026a4d;
          FUN_1002e346(pvVar12);
        }
      }
      FUN_100184e0(param_1,local_13c);
      uVar6 = FUN_10018200(local_110,local_13c);
      if (((char)uVar6 != '\0') && (pcVar7 = FUN_100182c0(local_110), *pcVar7 == '\x03')) {
        pcVar7 = FUN_100182c0(local_110);
        puVar8 = FUN_100142f0(pcVar7,(uint *)local_144);
        FUN_1000ec10((void *)((int)param_2 + 0x100),(int *)puVar8);
        if (0xf < local_130) {
          pvVar12 = local_144[0];
          if ((0xfff < local_130 + 1) &&
             (pvVar12 = *(void **)((int)local_144[0] + -4),
             0x1f < (uint)((int)local_144[0] + (-4 - (int)pvVar12)))) goto LAB_10026a52;
          FUN_1002e346(pvVar12);
        }
      }
      FUN_100184e0(param_1,local_13c);
      uVar6 = FUN_10018200(local_120,local_13c);
      if (((char)uVar6 == '\0') || (pcVar7 = FUN_100182c0(local_120), *pcVar7 != '\x03')) {
        if (*(char *)((int)param_2 + 0x130) != '\0') {
          if (0xf < *(uint *)((int)param_2 + 300)) {
            pvVar12 = *(void **)((int)param_2 + 0x118);
            pvVar10 = pvVar12;
            if ((0xfff < *(uint *)((int)param_2 + 300) + 1) &&
               (pvVar10 = *(void **)((int)pvVar12 + -4),
               0x1f < (uint)((int)pvVar12 + (-4 - (int)pvVar10)))) goto LAB_100269ce;
            FUN_1002e346(pvVar10);
          }
          *(undefined4 *)((int)param_2 + 0x128) = 0;
          *(undefined4 *)((int)param_2 + 300) = 0xf;
          *(undefined1 *)((int)param_2 + 0x118) = 0;
          *(undefined1 *)((int)param_2 + 0x130) = 0;
        }
      }
      else {
        pcVar7 = FUN_100182c0(local_120);
        puVar9 = FUN_100142f0(pcVar7,(uint *)local_144);
        puVar8 = (uint *)((int)param_2 + 0x118);
        if (*(char *)((int)param_2 + 0x130) == '\0') {
          *puVar8 = 0;
          *(undefined4 *)((int)param_2 + 0x128) = 0;
          *(undefined4 *)((int)param_2 + 300) = 0;
          uVar5 = puVar9[1];
          uVar2 = puVar9[2];
          uVar3 = puVar9[3];
          *puVar8 = *puVar9;
          *(uint *)((int)param_2 + 0x11c) = uVar5;
          *(uint *)((int)param_2 + 0x120) = uVar2;
          *(uint *)((int)param_2 + 0x124) = uVar3;
          *(undefined8 *)((int)param_2 + 0x128) = *(undefined8 *)(puVar9 + 4);
          puVar9[4] = 0;
          puVar9[5] = 0xf;
          *(undefined1 *)puVar9 = 0;
          *(undefined1 *)((int)param_2 + 0x130) = 1;
        }
        else {
          FUN_1000ec10(puVar8,(int *)puVar9);
        }
        if (0xf < local_130) {
          pvVar12 = local_144[0];
          if ((0xfff < local_130 + 1) &&
             (pvVar12 = *(void **)((int)local_144[0] + -4),
             0x1f < (uint)((int)local_144[0] + (-4 - (int)pvVar12)))) goto LAB_10026a57;
          FUN_1002e346(pvVar12);
        }
      }
      FUN_100184e0(param_1,local_13c);
      uVar6 = FUN_10018200(&local_64,local_13c);
      if (((char)uVar6 == '\0') || (pcVar7 = FUN_100182c0(&local_64), *pcVar7 != '\x03')) {
        if (*(char *)((int)param_2 + 0x14c) != '\0') {
          if (0xf < *(uint *)((int)param_2 + 0x148)) {
            pvVar12 = *(void **)((int)param_2 + 0x134);
            pvVar10 = pvVar12;
            if ((0xfff < *(uint *)((int)param_2 + 0x148) + 1) &&
               (pvVar10 = *(void **)((int)pvVar12 + -4),
               0x1f < (uint)((int)pvVar12 + (-4 - (int)pvVar10)))) goto LAB_100269ce;
            FUN_1002e346(pvVar10);
          }
          *(undefined4 *)((int)param_2 + 0x144) = 0;
          *(undefined4 *)((int)param_2 + 0x148) = 0xf;
          *(undefined1 *)((int)param_2 + 0x134) = 0;
          *(undefined1 *)((int)param_2 + 0x14c) = 0;
        }
      }
      else {
        pcVar7 = FUN_100182c0(&local_64);
        puVar9 = FUN_100142f0(pcVar7,(uint *)local_144);
        puVar8 = (uint *)((int)param_2 + 0x134);
        if (*(char *)((int)param_2 + 0x14c) == '\0') {
          *puVar8 = 0;
          *(undefined4 *)((int)param_2 + 0x144) = 0;
          *(undefined4 *)((int)param_2 + 0x148) = 0;
          uVar5 = puVar9[1];
          uVar2 = puVar9[2];
          uVar3 = puVar9[3];
          *puVar8 = *puVar9;
          *(uint *)((int)param_2 + 0x138) = uVar5;
          *(uint *)((int)param_2 + 0x13c) = uVar2;
          *(uint *)((int)param_2 + 0x140) = uVar3;
          *(undefined8 *)((int)param_2 + 0x144) = *(undefined8 *)(puVar9 + 4);
          puVar9[4] = 0;
          puVar9[5] = 0xf;
          *(undefined1 *)puVar9 = 0;
          *(undefined1 *)((int)param_2 + 0x14c) = 1;
        }
        else {
          FUN_1000ec10(puVar8,(int *)puVar9);
        }
        if (0xf < local_130) {
          pvVar12 = local_144[0];
          if ((0xfff < local_130 + 1) &&
             (pvVar12 = *(void **)((int)local_144[0] + -4),
             0x1f < (uint)((int)local_144[0] + (-4 - (int)pvVar12)))) goto LAB_10026a5c;
          FUN_1002e346(pvVar12);
        }
      }
      FUN_100184e0(param_1,local_13c);
      uVar6 = FUN_10018200(&local_78,local_13c);
      if ((char)uVar6 != '\0') {
        pcVar7 = FUN_100182c0((undefined4 *)&local_78);
        cVar1 = *pcVar7;
        if (((cVar1 == '\x05') || (cVar1 == '\x06')) || (cVar1 == '\a')) {
          pcVar7 = FUN_100182c0((undefined4 *)&local_78);
          cVar1 = *pcVar7;
          if ((cVar1 == '\x05') || (cVar1 == '\x06')) {
            uVar14 = *(ulonglong *)(pcVar7 + 8);
          }
          else {
            if (cVar1 != '\a') goto LAB_10026a61;
            uVar14 = FUN_1004d870();
          }
          uStack_70 = CONCAT31(uStack_70._1_3_,1);
          local_78._0_4_ = (undefined4)uVar14;
          local_78._4_4_ = (undefined4)(uVar14 >> 0x20);
          *(undefined4 *)((int)param_2 + 0x150) = (undefined4)local_78;
          *(undefined4 *)((int)param_2 + 0x154) = local_78._4_4_;
          *(undefined4 *)((int)param_2 + 0x158) = uStack_70;
          *(undefined4 *)((int)param_2 + 0x15c) = uStack_6c;
          local_78 = uVar14;
          goto LAB_100269ae;
        }
      }
      *(undefined1 *)((int)param_2 + 0x158) = 0;
LAB_100269ae:
      ExceptionList = local_1c;
      FUN_1002e315(local_24 ^ (uint)&stack0xfffffff0);
      return;
    }
    pcVar7 = FUN_100182c0(&local_44);
    puVar8 = FUN_100142f0(pcVar7,(uint *)local_144);
    FUN_1000ec10((void *)((int)param_2 + 0x90),(int *)puVar8);
    if (local_130 < 0x10) goto LAB_1002618f;
    pvVar12 = local_144[0];
    if ((local_130 + 1 < 0x1000) ||
       (pvVar12 = *(void **)((int)local_144[0] + -4),
       (uint)((int)local_144[0] + (-4 - (int)pvVar12)) < 0x20)) {
      FUN_1002e346(pvVar12);
      goto LAB_1002618f;
    }
  }
  else {
    pcVar7 = FUN_100182c0(local_90);
    puVar8 = FUN_100142f0(pcVar7,(uint *)local_144);
    FUN_1000ec10(param_2,(int *)puVar8);
    if (local_130 < 0x10) goto LAB_10025e3e;
    pvVar12 = local_144[0];
    if ((local_130 + 1 < 0x1000) ||
       (pvVar12 = *(void **)((int)local_144[0] + -4),
       (uint)((int)local_144[0] + (-4 - (int)pvVar12)) < 0x20)) {
      FUN_1002e346(pvVar12);
      goto LAB_10025e3e;
    }
LAB_100269ce:
    FUN_10032f7f();
LAB_100269d3:
    FUN_10032f7f();
LAB_100269d8:
    FUN_10032f7f();
LAB_100269dd:
    FUN_10032f7f();
LAB_100269e2:
    FUN_10032f7f();
LAB_100269e7:
    FUN_10032f7f();
  }
  FUN_10032f7f();
  pcVar7 = extraout_ECX;
LAB_100269f1:
  puVar8 = (uint *)FUN_1000f7b0(pcVar7);
  puVar8 = FUN_10005690(local_144,puVar8);
  local_14 = 0;
  puVar8 = FUN_10005f20(local_80,(uint *)"type must be boolean, but is ",puVar8);
  local_14 = CONCAT31(local_14._1_3_,1);
  FUN_1000ad90(local_12c,0x12e,puVar8);
                    /* WARNING: Subroutine does not return */
  __CxxThrowException_8(local_12c,&DAT_10067608);
}


// FUNCTION_END

// FUNCTION_START: FUN_10026ac0 @ 10026ac0