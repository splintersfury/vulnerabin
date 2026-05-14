undefined4 __thiscall FUN_10015f00(void *this,undefined4 *param_1)

{
  char *pcVar1;
  int iVar2;
  byte bVar3;
  code *pcVar4;
  undefined4 *puVar5;
  undefined8 uVar6;
  bool bVar7;
  byte bVar8;
  char cVar15;
  uint uVar9;
  int *piVar10;
  uint *puVar11;
  int iVar12;
  uint uVar13;
  uint uVar14;
  void *pvVar16;
  undefined1 *puVar17;
  uint uVar18;
  uint uVar19;
  int unaff_ESI;
  undefined1 *puVar20;
  undefined1 *unaff_EDI;
  undefined2 in_CS;
  byte in_AF;
  byte in_TF;
  byte in_IF;
  byte in_NT;
  byte in_AC;
  byte in_VIF;
  byte in_VIP;
  byte in_ID;
  undefined4 in_stack_fffffe80;
  undefined4 uVar21;
  undefined4 uVar22;
  void *local_168;
  uint *puStack_164;
  uint uStack_160;
  ushort *puStack_15c;
  int *piStack_158;
  uint local_154;
  char local_150 [8];
  undefined4 local_148;
  undefined4 local_144;
  char local_140 [8];
  undefined4 local_138;
  undefined4 local_134;
  char local_130 [8];
  undefined8 local_128;
  char local_120 [8];
  undefined8 local_118;
  char local_110 [8];
  undefined8 local_108;
  char local_100 [8];
  undefined8 local_f8;
  char local_f0 [8];
  undefined8 local_e8;
  char local_e0 [8];
  undefined8 local_d8;
  undefined **local_d0;
  undefined **local_cc;
  undefined4 local_c8 [2];
  undefined **local_c0;
  undefined **local_bc;
  undefined4 local_b8 [2];
  void *local_b0 [4];
  undefined4 local_a0;
  uint local_9c;
  void *local_98 [4];
  undefined4 local_88;
  uint local_84;
  void *local_80;
  void *local_7c;
  uint uStack_78;
  uint uStack_74;
  uint uStack_70;
  undefined8 local_6c;
  uint *local_64;
  undefined4 *local_60;
  char local_5a;
  char local_59;
  undefined4 local_58;
  undefined4 local_54;
  void *local_50;
  undefined4 uStack_4c;
  int iStack_48;
  uint uStack_44;
  undefined4 local_40;
  undefined4 *puStack_3c;
  undefined8 local_38;
  undefined4 local_30;
  uint local_24;
  undefined1 *puStack_20;
  void *local_1c;
  undefined1 *puStack_18;
  undefined1 local_14;
  undefined3 uStack_13;
  
  puStack_20 = &stack0xfffffffc;
  puStack_18 = &LAB_1004f219;
  local_1c = ExceptionList;
  uVar9 = DAT_10069054 ^ (uint)&stack0xfffffff0;
  ExceptionList = &local_1c;
  local_60 = param_1;
  local_50 = (void *)0x0;
  uStack_4c = 0;
  iStack_48 = 0;
  uStack_44 = 0;
  local_14 = 0;
  uStack_13 = 0;
  local_59 = '\0';
  local_80 = this;
  local_24 = uVar9;
LAB_10015f80:
  if (local_59 != '\0') {
    local_59 = '\0';
    goto LAB_100165c2;
  }
  switch(*(undefined4 *)((int)this + 0x28)) {
  case 1:
    uVar21 = FUN_100176f0(param_1,1);
    cVar15 = (char)uVar21;
    goto joined_r0x100161fc;
  case 2:
    uVar21 = FUN_100176f0(param_1,0);
    cVar15 = (char)uVar21;
joined_r0x100161fc:
    if (cVar15 == '\0') {
      local_59 = 0;
      goto LAB_10017459;
    }
    break;
  case 3:
    if (param_1[1] == param_1[2]) {
      local_14 = 0x12;
      local_140[0] = '\0';
      FUN_1000f600(&local_138,'\0');
      local_14 = 0;
      pcVar1 = (char *)*param_1;
      cVar15 = *pcVar1;
      *pcVar1 = local_140[0];
      uVar21 = *(undefined4 *)(pcVar1 + 0xc);
      uVar22 = *(undefined4 *)(pcVar1 + 8);
      *(undefined4 *)(pcVar1 + 0xc) = local_134;
      *(undefined4 *)(pcVar1 + 8) = local_138;
      local_140[0] = cVar15;
      local_138 = uVar22;
      local_134 = uVar21;
      FUN_1000e760(local_140);
      this = local_80;
      param_1 = local_60;
    }
    else {
      pcVar1 = *(char **)(param_1[2] + -4);
      if (*pcVar1 == '\x02') {
        local_64 = *(uint **)(pcVar1 + 8);
        puVar20 = (undefined1 *)local_64[1];
        if (puVar20 == (undefined1 *)local_64[2]) {
          in_stack_fffffe80 = 0x100162bb;
          FUN_1001b520(local_64,puVar20);
        }
        else {
          local_14 = 0x13;
          *puVar20 = 0;
          FUN_1000f600(puVar20 + 8,'\0');
          local_14 = 0;
          local_64[1] = local_64[1] + 0x10;
        }
      }
      else {
        local_14 = 0x14;
        local_150[0] = '\0';
        FUN_1000f600(&local_148,'\0');
        local_14 = 0;
        pcVar1 = (char *)param_1[4];
        cVar15 = *pcVar1;
        *pcVar1 = local_150[0];
        uVar21 = *(undefined4 *)(pcVar1 + 0xc);
        uVar22 = *(undefined4 *)(pcVar1 + 8);
        *(undefined4 *)(pcVar1 + 0xc) = local_144;
        *(undefined4 *)(pcVar1 + 8) = local_148;
        local_150[0] = cVar15;
        local_148 = uVar22;
        local_144 = uVar21;
        FUN_1000e760(local_150);
        this = local_80;
        param_1 = local_60;
      }
    }
    break;
  case 4:
    FUN_10019110(param_1,(uint *)((int)this + 0x58));
    break;
  case 5:
    local_38 = *(undefined8 *)((int)this + 0x80);
    if (param_1[1] == param_1[2]) {
      local_120[0] = '\0';
      local_118 = 0;
      in_stack_fffffe80 = 0x100164c4;
      FUN_1001bd80(local_120,(undefined4 *)&local_38);
      pcVar1 = (char *)*param_1;
      cVar15 = *pcVar1;
      *pcVar1 = local_120[0];
      uVar6 = *(undefined8 *)(pcVar1 + 8);
      *(undefined4 *)(pcVar1 + 0xc) = local_118._4_4_;
      *(undefined4 *)(pcVar1 + 8) = (undefined4)local_118;
      local_120[0] = cVar15;
      local_118 = uVar6;
      FUN_1000e760(local_120);
      this = local_80;
      param_1 = local_60;
    }
    else {
      pcVar1 = *(char **)(param_1[2] + -4);
      if (*pcVar1 == '\x02') {
        local_64 = *(uint **)(pcVar1 + 8);
        puVar20 = (undefined1 *)local_64[1];
        if (puVar20 == (undefined1 *)local_64[2]) {
          in_stack_fffffe80 = 0x10016550;
          FUN_1001b2a0(local_64,puVar20,(undefined4 *)&local_38);
        }
        else {
          *puVar20 = 0;
          *(undefined8 *)(puVar20 + 8) = 0;
          in_stack_fffffe80 = 0x1001653b;
          FUN_1001bd80(puVar20,(undefined4 *)&local_38);
          local_64[1] = local_64[1] + 0x10;
        }
      }
      else {
        local_130[0] = '\0';
        local_128 = 0;
        in_stack_fffffe80 = 0x10016574;
        FUN_1001bd80(local_130,(undefined4 *)&local_38);
        pcVar1 = (char *)param_1[4];
        cVar15 = *pcVar1;
        *pcVar1 = local_130[0];
        uVar6 = *(undefined8 *)(pcVar1 + 8);
        *(undefined4 *)(pcVar1 + 0xc) = local_128._4_4_;
        *(undefined4 *)(pcVar1 + 8) = (undefined4)local_128;
        local_130[0] = cVar15;
        local_128 = uVar6;
        FUN_1000e760(local_130);
        this = local_80;
        param_1 = local_60;
      }
    }
    break;
  case 6:
    local_58 = *(undefined4 *)((int)this + 0x78);
    local_54 = *(undefined4 *)((int)this + 0x7c);
    if (param_1[1] == param_1[2]) {
      local_100[0] = '\0';
      local_f8 = 0;
      in_stack_fffffe80 = 0x10016375;
      FUN_1001bda0(local_100,&local_58);
      pcVar1 = (char *)*param_1;
      cVar15 = *pcVar1;
      *pcVar1 = local_100[0];
      uVar6 = *(undefined8 *)(pcVar1 + 8);
      *(undefined4 *)(pcVar1 + 0xc) = local_f8._4_4_;
      *(undefined4 *)(pcVar1 + 8) = (undefined4)local_f8;
      local_100[0] = cVar15;
      local_f8 = uVar6;
      FUN_1000e760(local_100);
      this = local_80;
      param_1 = local_60;
    }
    else {
      pcVar1 = *(char **)(param_1[2] + -4);
      if (*pcVar1 == '\x02') {
        local_64 = *(uint **)(pcVar1 + 8);
        puVar20 = (undefined1 *)local_64[1];
        if (puVar20 == (undefined1 *)local_64[2]) {
          in_stack_fffffe80 = 0x10016404;
          FUN_1001b370(local_64,puVar20,&local_58);
        }
        else {
          *puVar20 = 0;
          *(undefined8 *)(puVar20 + 8) = 0;
          in_stack_fffffe80 = 0x100163ec;
          FUN_1001bda0(puVar20,&local_58);
          local_64[1] = local_64[1] + 0x10;
        }
      }
      else {
        local_110[0] = '\0';
        local_108 = 0;
        in_stack_fffffe80 = 0x1001642b;
        FUN_1001bda0(local_110,&local_58);
        pcVar1 = (char *)param_1[4];
        cVar15 = *pcVar1;
        *pcVar1 = local_110[0];
        uVar6 = *(undefined8 *)(pcVar1 + 8);
        *(undefined4 *)(pcVar1 + 0xc) = local_108._4_4_;
        *(undefined4 *)(pcVar1 + 8) = (undefined4)local_108;
        local_110[0] = cVar15;
        local_108 = uVar6;
        FUN_1000e760(local_110);
        this = local_80;
        param_1 = local_60;
      }
    }
    break;
  case 7:
    bVar7 = FUN_10014d50();
    if (!bVar7) {
      puVar11 = (uint *)FUN_100121a0((void *)((int)this + 0x30),&local_168);
      local_14 = 0xd;
      puVar11 = FUN_10005f20((uint *)local_98,(uint *)"number overflow parsing \'",puVar11);
      local_14 = 0xe;
      puVar11 = FUN_100055a0(puVar11,(uint *)&DAT_1005eec0);
      local_7c = (void *)*puVar11;
      uStack_78 = puVar11[1];
      uStack_74 = puVar11[2];
      uStack_70 = puVar11[3];
      local_6c = *(undefined8 *)(puVar11 + 4);
      puVar11[4] = 0;
      puVar11[5] = 0xf;
      *(undefined1 *)puVar11 = 0;
      local_14 = 0xf;
      iVar12 = FUN_1000af70(&local_cc,0x196,(uint *)&local_7c);
      local_14 = 0x10;
      uVar21 = 0x10016bd9;
      FUN_100121a0((void *)((int)this + 0x30),local_b0);
      local_14 = 0x11;
      uVar13 = FUN_10011680(local_60,in_stack_fffffe80,uVar21,iVar12);
      local_59 = (char)uVar13;
      if (0xf < local_9c) {
        pvVar16 = local_b0[0];
        if ((0xfff < local_9c + 1) &&
           (pvVar16 = *(void **)((int)local_b0[0] + -4),
           0x1f < (uint)((int)local_b0[0] + (-4 - (int)pvVar16)))) goto LAB_100174af;
        FUN_1002e346(pvVar16);
      }
      local_a0 = 0;
      local_9c = 0xf;
      local_b0[0] = (void *)((uint)local_b0[0] & 0xffffff00);
      local_bc = std::exception::vftable;
      ___std_exception_destroy(local_b8);
      local_cc = std::exception::vftable;
      ___std_exception_destroy(local_c8);
      if (0xf < local_6c._4_4_) {
        pvVar16 = local_7c;
        if ((0xfff < local_6c._4_4_ + 1) &&
           (pvVar16 = *(void **)((int)local_7c - 4),
           0x1f < (uint)((int)local_7c + (-4 - (int)pvVar16)))) goto LAB_100174af;
        FUN_1002e346(pvVar16);
      }
      if (0xf < local_84) {
        pvVar16 = local_98[0];
        if ((0xfff < local_84 + 1) &&
           (pvVar16 = *(void **)((int)local_98[0] + -4),
           0x1f < (uint)((int)local_98[0] + (-4 - (int)pvVar16)))) goto LAB_100174af;
        FUN_1002e346(pvVar16);
      }
      local_88 = 0;
      local_84 = 0xf;
      local_98[0] = (void *)((uint)local_98[0] & 0xffffff00);
      if (local_154 < 0x10) goto LAB_10017459;
      goto LAB_100169bf;
    }
    local_40 = *(undefined4 *)((int)this + 0x88);
    puStack_3c = *(undefined4 **)((int)this + 0x8c);
    if (param_1[1] == param_1[2]) {
      local_e0[0] = '\0';
      local_d8 = 0;
      in_stack_fffffe80 = 0x100160ee;
      FUN_1001bd50(local_e0,(undefined8 *)&local_40);
      pcVar1 = (char *)*param_1;
      cVar15 = *pcVar1;
      *pcVar1 = local_e0[0];
      uVar6 = *(undefined8 *)(pcVar1 + 8);
      *(undefined4 *)(pcVar1 + 0xc) = local_d8._4_4_;
      *(undefined4 *)(pcVar1 + 8) = (undefined4)local_d8;
      local_e0[0] = cVar15;
      local_d8 = uVar6;
      FUN_1000e760(local_e0);
      this = local_80;
      param_1 = local_60;
    }
    else {
      pcVar1 = *(char **)(param_1[2] + -4);
      if (*pcVar1 == '\x02') {
        local_64 = *(uint **)(pcVar1 + 8);
        puVar20 = (undefined1 *)local_64[1];
        if (puVar20 == (undefined1 *)local_64[2]) {
          in_stack_fffffe80 = 0x1001617d;
          FUN_1001b1d0(local_64,puVar20,(undefined8 *)&local_40);
        }
        else {
          *puVar20 = 0;
          *(undefined8 *)(puVar20 + 8) = 0;
          in_stack_fffffe80 = 0x10016165;
          FUN_1001bd50(puVar20,(undefined8 *)&local_40);
          local_64[1] = local_64[1] + 0x10;
        }
      }
      else {
        local_f0[0] = '\0';
        local_e8 = 0;
        in_stack_fffffe80 = 0x100161a4;
        FUN_1001bd50(local_f0,(undefined8 *)&local_40);
        pcVar1 = (char *)param_1[4];
        cVar15 = *pcVar1;
        *pcVar1 = local_f0[0];
        uVar6 = *(undefined8 *)(pcVar1 + 8);
        *(undefined4 *)(pcVar1 + 0xc) = local_e8._4_4_;
        *(undefined4 *)(pcVar1 + 8) = (undefined4)local_e8;
        local_f0[0] = cVar15;
        local_e8 = uVar6;
        FUN_1000e760(local_f0);
        this = local_80;
        param_1 = local_60;
      }
    }
    break;
  case 8:
    local_5a = '\x02';
    local_64 = (uint *)FUN_10018ff0(param_1,&local_5a);
    puVar11 = (uint *)param_1[2];
    if (puVar11 == (uint *)param_1[3]) {
      in_stack_fffffe80 = 0x10016071;
      FUN_1001a820(param_1 + 1,puVar11,(uint *)&local_64);
    }
    else {
      *puVar11 = (uint)local_64;
      param_1[2] = param_1[2] + 4;
    }
    iVar12 = FUN_10012320((undefined4 *)((int)this + 0x30));
    *(int *)((int)this + 0x28) = iVar12;
    if (iVar12 != 10) {
      local_5a = '\x01';
      FUN_100125f0(&local_50,&local_5a);
      goto LAB_10015f80;
    }
    param_1[2] = param_1[2] + -4;
    break;
  case 9:
    local_5a = '\x01';
    local_64 = (uint *)FUN_10018ff0(param_1,&local_5a);
    puVar11 = (uint *)param_1[2];
    if (puVar11 == (uint *)param_1[3]) {
      in_stack_fffffe80 = 0x10015fcd;
      FUN_1001a820(param_1 + 1,puVar11,(uint *)&local_64);
    }
    else {
      *puVar11 = (uint)local_64;
      param_1[2] = param_1[2] + 4;
    }
    puStack_3c = (undefined4 *)((int)this + 0x30);
    iVar12 = FUN_10012320(puStack_3c);
    *(int *)((int)this + 0x28) = iVar12;
    if (iVar12 == 0xb) {
      param_1[2] = param_1[2] + -4;
      break;
    }
    if (iVar12 != 4) {
      local_6c = 0xf00000000;
      local_7c = (void *)0x0;
      FUN_10008e70(&local_7c,(uint *)"object key",10);
      local_14 = 3;
      puVar11 = FUN_10011be0(local_98,4,(uint *)&local_7c);
      local_14 = 4;
      local_30 = *(undefined4 *)((int)this + 0x48);
      local_38 = *(undefined8 *)((int)this + 0x40);
      uVar21 = 0x10016a4d;
      iVar12 = FUN_1000a5b0((undefined4 *)&local_38,puVar11);
      local_14 = 5;
      uVar22 = 0x10016a64;
      FUN_100121a0((void *)((int)this + 0x30),local_b0);
      local_14 = 6;
      uVar13 = FUN_10011680(local_60,uVar21,uVar22,iVar12);
      local_59 = (char)uVar13;
      if (0xf < local_9c) {
        pvVar16 = local_b0[0];
        if ((0xfff < local_9c + 1) &&
           (pvVar16 = *(void **)((int)local_b0[0] + -4),
           0x1f < (uint)((int)local_b0[0] + (-4 - (int)pvVar16)))) goto LAB_100174af;
        FUN_1002e346(pvVar16);
      }
      local_a0 = 0;
      local_9c = 0xf;
      local_b0[0] = (void *)((uint)local_b0[0] & 0xffffff00);
      local_c0 = std::exception::vftable;
      ___std_exception_destroy(&local_bc);
      local_d0 = std::exception::vftable;
      ___std_exception_destroy(&local_cc);
      if (local_84 < 0x10) goto LAB_10016b35;
      pvVar16 = local_98[0];
      if ((0xfff < local_84 + 1) &&
         (pvVar16 = *(void **)((int)local_98[0] + -4),
         0x1f < (uint)((int)local_98[0] + (-4 - (int)pvVar16)))) goto LAB_100174af;
      FUN_1002e346(pvVar16);
      goto LAB_10016b35;
    }
    piVar10 = FUN_100183d0(*(void **)(*(int *)(param_1[2] + -4) + 8),(uint *)((int)this + 0x58));
    param_1[4] = piVar10;
    iVar12 = FUN_10012320((undefined4 *)((int)this + 0x30));
    *(int *)((int)this + 0x28) = iVar12;
    if (iVar12 == 0xc) goto code_r0x1001601d;
    local_6c = 0xf00000000;
    local_7c = (void *)0x0;
    FUN_10008e70(&local_7c,(uint *)"object separator",0x10);
    local_14 = 7;
    puVar11 = FUN_10011be0(local_b0,0xc,(uint *)&local_7c);
    local_14 = 8;
    local_30 = *(undefined4 *)((int)this + 0x48);
    local_38 = *(undefined8 *)((int)this + 0x40);
    uVar21 = 0x100168b2;
    iVar12 = FUN_1000a5b0((undefined4 *)&local_38,puVar11);
    local_14 = 9;
    uVar22 = 0x100168ca;
    FUN_100121a0(puStack_3c,local_98);
    local_14 = 10;
    uVar13 = FUN_10011680(param_1,uVar21,uVar22,iVar12);
    local_59 = (char)uVar13;
    if (local_84 < 0x10) {
LAB_10016913:
      local_88 = 0;
      local_84 = 0xf;
      local_98[0] = (void *)((uint)local_98[0] & 0xffffff00);
      local_c0 = std::exception::vftable;
      ___std_exception_destroy(&local_bc);
      local_d0 = std::exception::vftable;
      ___std_exception_destroy(&local_cc);
      if (0xf < local_9c) {
        pvVar16 = local_b0[0];
        if ((0xfff < local_9c + 1) &&
           (pvVar16 = *(void **)((int)local_b0[0] + -4),
           0x1f < (uint)((int)local_b0[0] + (-4 - (int)pvVar16)))) goto LAB_100174af;
        FUN_1002e346(pvVar16);
      }
      local_a0 = 0;
      local_9c = 0xf;
      local_b0[0] = (void *)((uint)local_b0[0] & 0xffffff00);
LAB_100169af:
      local_168 = local_7c;
      local_154 = local_6c._4_4_;
      if (0xf < local_6c._4_4_) {
LAB_100169bf:
        pvVar16 = local_168;
        if ((0xfff < local_154 + 1) &&
           (pvVar16 = *(void **)((int)local_168 - 4),
           0x1f < (uint)((int)local_168 + (-4 - (int)pvVar16)))) goto LAB_100174af;
LAB_10017449:
        FUN_1002e346(pvVar16);
      }
LAB_10017459:
      if (local_50 == (void *)0x0) {
LAB_1001748c:
        ExceptionList = local_1c;
        uVar21 = FUN_1002e315(local_24 ^ (uint)&stack0xfffffff0);
        return uVar21;
      }
      pvVar16 = local_50;
      if (((iStack_48 - (int)local_50 & 0xfffffffcU) < 0x1000) ||
         (pvVar16 = *(void **)((int)local_50 + -4),
         (uint)((int)local_50 + (-4 - (int)pvVar16)) < 0x20)) {
        FUN_1002e346(pvVar16);
        goto LAB_1001748c;
      }
    }
    else {
      pvVar16 = local_98[0];
      if ((local_84 + 1 < 0x1000) ||
         (pvVar16 = *(void **)((int)local_98[0] + -4),
         (uint)((int)local_98[0] + (-4 - (int)pvVar16)) < 0x20)) {
        FUN_1002e346(pvVar16);
        goto LAB_10016913;
      }
    }
LAB_100174af:
    FUN_10032f7f();
    *piStack_158 = *piStack_158 + uStack_160;
    uVar19 = (uint)&local_154 | *(uint *)(uStack_160 + 1);
    *(char *)(piStack_158 + 0x19) = (char)piStack_158[0x19] + (char)((uint)puStack_164 >> 8);
    *piStack_158 = *piStack_158 + uStack_160;
    cVar15 = (char)((uint)piStack_158 >> 8);
    *(char *)((int)(puStack_15c + 8) + (int)piStack_158) = cVar15;
    bVar7 = 9 < ((byte)piStack_158 & 0xf);
    bVar3 = bVar7 | in_AF;
    uVar13 = CONCAT31((int3)((uint)piStack_158 >> 8),(byte)piStack_158 + bVar3 * -6) & 0xffffff0f;
    bVar8 = (byte)uVar13;
    cVar15 = cVar15 - bVar3;
    puVar11 = (uint *)CONCAT22((short)(uVar13 >> 0x10),CONCAT11(cVar15,bVar8));
    *puStack_15c = *puStack_15c + (ushort)bVar3 * ((bVar8 & 3) - (*puStack_15c & 3));
    *(char *)(uStack_160 + 0x40100160) = *(char *)(uStack_160 + 0x40100160) + cVar15 + bVar3;
    *(uint **)(uVar19 - 4) = puVar11;
    *(ushort **)(uVar19 - 8) = puStack_15c;
    *(uint *)(uVar19 - 0xc) = uStack_160;
    *(uint **)(uVar19 - 0x10) = puStack_164;
    *(uint *)(uVar19 - 0x14) = uVar19;
    *(int *)(uVar19 - 0x18) = unaff_ESI;
    *(undefined1 **)(uVar19 - 0x1c) = unaff_EDI;
    *(uint *)(uVar19 - 0x20) = uVar9;
    uVar9 = *puVar11;
    uVar13 = *puVar11;
    *puVar11 = *puVar11 + uStack_160;
    *(uint *)(uVar19 - 0x24) =
         (uint)(in_NT & 1) * 0x4000 | (uint)SCARRY4(uVar13,uStack_160) * 0x800 |
         (uint)(in_IF & 1) * 0x200 | (uint)(in_TF & 1) * 0x100 | (uint)((int)*puVar11 < 0) * 0x80 |
         (uint)(*puVar11 == 0) * 0x40 | (uint)(bVar7 | in_AF & 1) * 0x10 |
         (uint)((POPCOUNT(*puVar11 & 0xff) & 1U) == 0) * 4 | (uint)CARRY4(uVar9,uStack_160) |
         (uint)(in_ID & 1) * 0x200000 | (uint)(in_VIP & 1) * 0x100000 | (uint)(in_VIF & 1) * 0x80000
         | (uint)(in_AC & 1) * 0x40000;
    puVar5 = *(undefined4 **)(uVar19 - 0x24);
    *puVar11 = *puVar11 + uStack_160;
    if ((POPCOUNT(*puVar11 & 0xff) & 1U) == 0) {
      *puVar11 = *puVar11 + uStack_160;
      puVar20 = unaff_EDI;
      if ((POPCOUNT(*puVar11 & 0xff) & 1U) != 0) goto LAB_1001754c;
code_r0x100174de:
      *puVar11 = *puVar11 + uStack_160;
      if ((POPCOUNT(*puVar11 & 0xff) & 1U) != 0) {
        uVar9 = (uint)puVar5 & 0xffffffe0;
        *(uint **)(uVar9 - 4) = puVar11;
        goto code_r0x10017556;
      }
      *puVar11 = *puVar11 + uStack_160;
      unaff_EDI = puVar20;
      if ((POPCOUNT(*puVar11 & 0xff) & 1U) == 0) {
        *puVar11 = *puVar11 + uStack_160;
        *(undefined2 *)(uVar19 - 0x24) = in_CS;
        uVar21 = in((short)uStack_160);
        *puVar5 = uVar21;
        *puVar11 = *puVar11 + uStack_160;
        pcVar4 = (code *)swi(3);
        uVar21 = (*pcVar4)();
        return uVar21;
      }
    }
    else {
      *(byte *)puVar11 = (char)*puVar11 + bVar8;
LAB_1001754c:
      pcVar1 = (char *)(unaff_ESI + -0x187cdc88);
      *pcVar1 = *pcVar1 + (char)puStack_15c;
      if (puStack_15c != (ushort *)0x1 && *pcVar1 != '\0') {
        puVar20 = unaff_EDI + 1;
        out(*unaff_EDI,(short)uStack_160);
        goto code_r0x100174de;
      }
    }
    uVar9 = (int)puVar5 + 1;
    puVar20 = unaff_EDI;
code_r0x10017556:
    puVar17 = (undefined1 *)(*(int *)(unaff_ESI + -4) + uVar9);
    uVar13 = *(uint *)(unaff_ESI + -8);
    *(undefined1 **)(unaff_ESI + -4) = puVar17;
    *puVar17 = **(undefined1 **)(unaff_ESI + 0xc);
    uVar14 = *puStack_164;
    if (uVar13 == puStack_164[1]) {
      *(uint *)(uVar19 - 0x24) = puStack_164[1] - uVar14;
      *(uint *)(uVar19 - 0x28) = uVar14;
      *(uint *)(uVar19 - 0x2c) = uVar9;
      *(undefined4 *)(uVar19 - 0x30) = 0x100175af;
      FUN_100301d0(*(uint **)(uVar19 - 0x2c),*(uint **)(uVar19 - 0x28),*(uint *)(uVar19 - 0x24));
    }
    else {
      *(uint *)(uVar19 - 0x24) = uVar13 - uVar14;
      *(uint *)(uVar19 - 0x28) = uVar14;
      *(uint *)(uVar19 - 0x2c) = uVar9;
      *(undefined4 *)(uVar19 - 0x30) = 0x100175be;
      FUN_100301d0(*(uint **)(uVar19 - 0x2c),*(uint **)(uVar19 - 0x28),*(uint *)(uVar19 - 0x24));
      iVar12 = *(int *)(unaff_ESI + -8);
      *(uint *)(uVar19 - 0x30) = puStack_164[1] - iVar12;
      iVar2 = *(int *)(unaff_ESI + -4);
      *(int *)(uVar19 - 0x34) = iVar12;
      *(int *)(uVar19 - 0x38) = iVar2 + 1;
      *(undefined4 *)(uVar19 - 0x3c) = 0x100175d2;
      FUN_100301d0(*(uint **)(uVar19 - 0x38),*(uint **)(uVar19 - 0x34),*(uint *)(uVar19 - 0x30));
    }
    uVar13 = *puStack_164;
    if (uVar13 != 0) {
      uVar18 = puStack_164[2] - uVar13;
      uVar14 = uVar13;
      if (0xfff < uVar18) {
        uVar14 = *(uint *)(uVar13 - 4);
        uVar18 = uVar18 + 0x23;
        if (0x1f < (uVar13 - uVar14) - 4) {
          *(undefined4 *)(uVar19 - 0x24) = 0x10017625;
          FUN_10032f7f();
          *(undefined4 *)(uVar19 - 0x24) = 0x1001762a;
          FUN_10017fa0();
          *(undefined4 *)(uVar19 - 0x24) = 0x1001762f;
          FUN_10001fb0();
          pcVar4 = (code *)swi(3);
          uVar21 = (*pcVar4)();
          return uVar21;
        }
      }
      *(uint *)(uVar19 - 0x24) = uVar18;
      *(uint *)(uVar19 - 0x28) = uVar14;
      *(undefined4 *)(uVar19 - 0x2c) = 0x10017601;
      FUN_1002e346(*(void **)(uVar19 - 0x28));
    }
    iVar12 = *(int *)(unaff_ESI + -0xc);
    uVar21 = *(undefined4 *)(unaff_ESI + -4);
    *puStack_164 = uVar9;
    puStack_164[1] = iVar12 + uVar9;
    puStack_164[2] = (uint)(puVar20 + uVar9);
    return uVar21;
  default:
    local_6c = 0xf00000000;
    local_7c = (void *)0x0;
    FUN_10008e70(&local_7c,(uint *)"value",5);
    local_14 = 0x19;
    puVar11 = FUN_10011be0(local_98,0x10,(uint *)&local_7c);
    local_14 = 0x1a;
    local_30 = *(undefined4 *)((int)this + 0x48);
    local_38 = *(undefined8 *)((int)this + 0x40);
    uVar21 = 0x10016ee2;
    iVar12 = FUN_1000a5b0((undefined4 *)&local_38,puVar11);
    local_14 = 0x1b;
    uVar22 = 0x10016ef9;
    FUN_100121a0((void *)((int)this + 0x30),local_b0);
    local_14 = 0x1c;
    uVar13 = FUN_10011680(local_60,uVar21,uVar22,iVar12);
    local_59 = (char)uVar13;
    if (0xf < local_9c) {
      pvVar16 = local_b0[0];
      if ((0xfff < local_9c + 1) &&
         (pvVar16 = *(void **)((int)local_b0[0] + -4),
         0x1f < (uint)((int)local_b0[0] + (-4 - (int)pvVar16)))) goto LAB_100174af;
      FUN_1002e346(pvVar16);
    }
    local_a0 = 0;
    local_9c = 0xf;
    local_b0[0] = (void *)((uint)local_b0[0] & 0xffffff00);
    local_c0 = std::exception::vftable;
    ___std_exception_destroy(&local_bc);
    local_d0 = std::exception::vftable;
    ___std_exception_destroy(&local_cc);
    if (local_84 < 0x10) goto LAB_10016b35;
    pvVar16 = local_98[0];
    if ((0xfff < local_84 + 1) &&
       (pvVar16 = *(void **)((int)local_98[0] + -4),
       0x1f < (uint)((int)local_98[0] + (-4 - (int)pvVar16)))) goto LAB_100174af;
    FUN_1002e346(pvVar16);
    local_88 = 0;
    local_84 = 0xf;
    local_98[0] = (void *)((uint)local_98[0] & 0xffffff00);
    goto LAB_100169af;
  case 0xe:
    local_6c = 0xf00000000;
    local_7c = (void *)0x0;
    FUN_10008e70(&local_7c,(uint *)"value",5);
    local_14 = 0x15;
    puVar11 = FUN_10011be0(local_98,0,(uint *)&local_7c);
    local_14 = 0x16;
    local_30 = *(undefined4 *)((int)this + 0x48);
    local_38 = *(undefined8 *)((int)this + 0x40);
    uVar21 = 0x10016d75;
    iVar12 = FUN_1000a5b0((undefined4 *)&local_38,puVar11);
    local_14 = 0x17;
    uVar22 = 0x10016d8c;
    FUN_100121a0((void *)((int)this + 0x30),local_b0);
    local_14 = 0x18;
    uVar13 = FUN_10011680(local_60,uVar21,uVar22,iVar12);
    local_59 = (char)uVar13;
    if (0xf < local_9c) {
      pvVar16 = local_b0[0];
      if ((0xfff < local_9c + 1) &&
         (pvVar16 = *(void **)((int)local_b0[0] + -4),
         0x1f < (uint)((int)local_b0[0] + (-4 - (int)pvVar16)))) goto LAB_100174af;
      FUN_1002e346(pvVar16);
    }
    local_a0 = 0;
    local_9c = 0xf;
    local_b0[0] = (void *)((uint)local_b0[0] & 0xffffff00);
    local_c0 = std::exception::vftable;
    ___std_exception_destroy(&local_bc);
    local_d0 = std::exception::vftable;
    ___std_exception_destroy(&local_cc);
    if (local_84 < 0x10) goto LAB_10016b35;
    pvVar16 = local_98[0];
    if ((0xfff < local_84 + 1) &&
       (pvVar16 = *(void **)((int)local_98[0] + -4),
       0x1f < (uint)((int)local_98[0] + (-4 - (int)pvVar16)))) goto LAB_100174af;
    FUN_1002e346(pvVar16);
    local_88 = 0;
    local_84 = 0xf;
    local_98[0] = (void *)((uint)local_98[0] & 0xffffff00);
    goto LAB_100169af;
  }
LAB_100165c2:
  if (uStack_44 == 0) {
    local_59 = 1;
    goto LAB_10017459;
  }
  if (((int)uStack_44 < 0) && (uStack_44 != 0)) {
    iVar12 = -((~uStack_44 >> 5) * 4 + 4);
  }
  else {
    iVar12 = (uStack_44 >> 5) * 4;
  }
  uVar13 = (uStack_44 & 0x1f) - 1;
  if ((uStack_44 & 0x1f) == 0) {
    iVar2 = -((~uVar13 >> 5) * 4 + 4);
  }
  else {
    iVar2 = (uVar13 >> 5) * 4;
  }
  local_64 = (uint *)((int)local_50 + iVar2 + iVar12);
  puStack_3c = (undefined4 *)((int)this + 0x30);
  if ((*local_64 & 1 << ((byte)uVar13 & 0x1f)) == 0) {
    iVar12 = FUN_10012320(puStack_3c);
    *(int *)((int)this + 0x28) = iVar12;
    if (iVar12 == 0xd) {
      iVar12 = FUN_10012320((undefined4 *)((int)this + 0x30));
      *(int *)((int)this + 0x28) = iVar12;
      if (iVar12 == 4) {
        piVar10 = FUN_100183d0(*(void **)(*(int *)(param_1[2] + -4) + 8),(uint *)((int)this + 0x58))
        ;
        param_1[4] = piVar10;
        iVar12 = FUN_10012320((undefined4 *)((int)this + 0x30));
        *(int *)((int)this + 0x28) = iVar12;
        if (iVar12 == 0xc) {
          uVar21 = FUN_10012320((undefined4 *)((int)this + 0x30));
          *(undefined4 *)((int)this + 0x28) = uVar21;
          goto LAB_10015f80;
        }
        local_6c = 0xf00000000;
        local_7c = (void *)0x0;
        FUN_10008e70(&local_7c,(uint *)"object separator",0x10);
        local_14 = 0x25;
        puVar11 = FUN_10011be0(local_98,0xc,(uint *)&local_7c);
        local_14 = 0x26;
        local_30 = *(undefined4 *)((int)this + 0x48);
        local_38 = *(undefined8 *)((int)this + 0x40);
        uVar21 = 0x1001704c;
        iVar12 = FUN_1000a5b0((undefined4 *)&local_38,puVar11);
        local_14 = 0x27;
        uVar22 = 0x10017064;
        FUN_100121a0(puStack_3c,local_b0);
        local_14 = 0x28;
        uVar13 = FUN_10011680(param_1,uVar21,uVar22,iVar12);
        local_59 = (char)uVar13;
        if (0xf < local_9c) {
          pvVar16 = local_b0[0];
          if ((0xfff < local_9c + 1) &&
             (pvVar16 = *(void **)((int)local_b0[0] + -4),
             0x1f < (uint)((int)local_b0[0] + (-4 - (int)pvVar16)))) goto LAB_100174af;
          FUN_1002e346(pvVar16);
        }
        local_a0 = 0;
        local_9c = 0xf;
        local_b0[0] = (void *)((uint)local_b0[0] & 0xffffff00);
        local_c0 = std::exception::vftable;
        ___std_exception_destroy(&local_bc);
        local_d0 = std::exception::vftable;
        ___std_exception_destroy(&local_cc);
        if (0xf < local_84) {
          pvVar16 = local_98[0];
          if ((0xfff < local_84 + 1) &&
             (pvVar16 = *(void **)((int)local_98[0] + -4),
             0x1f < (uint)((int)local_98[0] + (-4 - (int)pvVar16)))) goto LAB_100174af;
          FUN_1002e346(pvVar16);
          local_88 = 0;
          local_84 = 0xf;
          local_98[0] = (void *)((uint)local_98[0] & 0xffffff00);
          goto LAB_100169af;
        }
      }
      else {
        local_6c = 0xf00000000;
        local_7c = (void *)0x0;
        FUN_10008e70(&local_7c,(uint *)"object key",10);
        local_14 = 0x21;
        puVar11 = FUN_10011be0(local_98,4,(uint *)&local_7c);
        local_14 = 0x22;
        local_30 = *(undefined4 *)((int)this + 0x48);
        local_38 = *(undefined8 *)((int)this + 0x40);
        uVar21 = 0x100171b9;
        iVar12 = FUN_1000a5b0((undefined4 *)&local_38,puVar11);
        local_14 = 0x23;
        uVar22 = 0x100171d0;
        FUN_100121a0((void *)((int)this + 0x30),local_b0);
        local_14 = 0x24;
        uVar13 = FUN_10011680(local_60,uVar21,uVar22,iVar12);
        local_59 = (char)uVar13;
        if (0xf < local_9c) {
          pvVar16 = local_b0[0];
          if ((0xfff < local_9c + 1) &&
             (pvVar16 = *(void **)((int)local_b0[0] + -4),
             0x1f < (uint)((int)local_b0[0] + (-4 - (int)pvVar16)))) goto LAB_100174af;
          FUN_1002e346(pvVar16);
        }
        local_a0 = 0;
        local_9c = 0xf;
        local_b0[0] = (void *)((uint)local_b0[0] & 0xffffff00);
        local_c0 = std::exception::vftable;
        ___std_exception_destroy(&local_bc);
        local_d0 = std::exception::vftable;
        ___std_exception_destroy(&local_cc);
        if (0xf < local_84) {
          pvVar16 = local_98[0];
          if ((0xfff < local_84 + 1) &&
             (pvVar16 = *(void **)((int)local_98[0] + -4),
             0x1f < (uint)((int)local_98[0] + (-4 - (int)pvVar16)))) goto LAB_100174af;
          FUN_1002e346(pvVar16);
          local_88 = 0;
          local_84 = 0xf;
          local_98[0] = (void *)((uint)local_98[0] & 0xffffff00);
          goto LAB_100169af;
        }
      }
LAB_10016b35:
      local_88 = 0;
      local_84 = 0xf;
      local_98[0] = (void *)((uint)local_98[0] & 0xffffff00);
      goto LAB_100169af;
    }
    if (iVar12 != 0xb) {
      local_6c = 0xf00000000;
      local_7c = (void *)0x0;
      FUN_10008e70(&local_7c,(uint *)"object",6);
      local_14 = 0x29;
      puVar11 = FUN_10011be0(local_98,0xb,(uint *)&local_7c);
      local_14 = 0x2a;
      local_30 = *(undefined4 *)((int)this + 0x48);
      local_38 = *(undefined8 *)((int)this + 0x40);
      uVar21 = 0x10017326;
      iVar12 = FUN_1000a5b0((undefined4 *)&local_38,puVar11);
      local_14 = 0x2b;
      uVar22 = 0x1001733d;
      FUN_100121a0((void *)((int)this + 0x30),local_b0);
      local_14 = 0x2c;
      uVar13 = FUN_10011680(local_60,uVar21,uVar22,iVar12);
      local_59 = (char)uVar13;
      if (0xf < local_9c) {
        pvVar16 = local_b0[0];
        if ((0xfff < local_9c + 1) &&
           (pvVar16 = *(void **)((int)local_b0[0] + -4),
           0x1f < (uint)((int)local_b0[0] + (-4 - (int)pvVar16)))) goto LAB_100174af;
        FUN_1002e346(pvVar16);
      }
      local_a0 = 0;
      local_9c = 0xf;
      local_b0[0] = (void *)((uint)local_b0[0] & 0xffffff00);
      local_c0 = std::exception::vftable;
      ___std_exception_destroy(&local_bc);
      local_d0 = std::exception::vftable;
      ___std_exception_destroy(&local_cc);
      if (0xf < local_84) {
        pvVar16 = local_98[0];
        if ((0xfff < local_84 + 1) &&
           (pvVar16 = *(void **)((int)local_98[0] + -4),
           0x1f < (uint)((int)local_98[0] + (-4 - (int)pvVar16)))) goto LAB_100174af;
        FUN_1002e346(pvVar16);
      }
      local_88 = 0;
      local_84 = 0xf;
      local_98[0] = (void *)((uint)local_98[0] & 0xffffff00);
      if (local_6c._4_4_ < 0x10) goto LAB_10017459;
      pvVar16 = local_7c;
      if ((local_6c._4_4_ + 1 < 0x1000) ||
         (pvVar16 = *(void **)((int)local_7c - 4),
         (uint)((int)local_7c + (-4 - (int)pvVar16)) < 0x20)) goto LAB_10017449;
      goto LAB_100174af;
    }
  }
  else {
    iVar12 = FUN_10012320(puStack_3c);
    *(int *)((int)this + 0x28) = iVar12;
    if (iVar12 == 0xd) {
      uVar21 = FUN_10012320((undefined4 *)((int)this + 0x30));
      *(undefined4 *)((int)this + 0x28) = uVar21;
      goto LAB_10015f80;
    }
    if (iVar12 != 10) {
      local_6c = 0xf00000000;
      local_7c = (void *)0x0;
      FUN_10008e70(&local_7c,(uint *)"array",5);
      local_14 = 0x1d;
      puVar11 = FUN_10011be0(local_98,10,(uint *)&local_7c);
      local_14 = 0x1e;
      local_30 = *(undefined4 *)((int)this + 0x48);
      local_38 = *(undefined8 *)((int)this + 0x40);
      uVar21 = 0x100166cf;
      iVar12 = FUN_1000a5b0((undefined4 *)&local_38,puVar11);
      local_14 = 0x1f;
      uVar22 = 0x100166e6;
      FUN_100121a0((void *)((int)this + 0x30),local_b0);
      local_14 = 0x20;
      uVar13 = FUN_10011680(local_60,uVar21,uVar22,iVar12);
      local_59 = (char)uVar13;
      if (0xf < local_9c) {
        pvVar16 = local_b0[0];
        if ((0xfff < local_9c + 1) &&
           (pvVar16 = *(void **)((int)local_b0[0] + -4),
           0x1f < (uint)((int)local_b0[0] + (-4 - (int)pvVar16)))) goto LAB_100174af;
        FUN_1002e346(pvVar16);
      }
      local_a0 = 0;
      local_9c = 0xf;
      local_b0[0] = (void *)((uint)local_b0[0] & 0xffffff00);
      local_c0 = std::exception::vftable;
      ___std_exception_destroy(&local_bc);
      local_d0 = std::exception::vftable;
      ___std_exception_destroy(&local_cc);
      if (local_84 < 0x10) goto LAB_10016b35;
      pvVar16 = local_98[0];
      if ((0xfff < local_84 + 1) &&
         (pvVar16 = *(void **)((int)local_98[0] + -4),
         0x1f < (uint)((int)local_98[0] + (-4 - (int)pvVar16)))) goto LAB_100174af;
      FUN_1002e346(pvVar16);
      local_88 = 0;
      local_84 = 0xf;
      local_98[0] = (void *)((uint)local_98[0] & 0xffffff00);
      goto LAB_100169af;
    }
  }
  param_1[2] = param_1[2] + -4;
  FUN_10017fb0((int *)&local_50);
  local_59 = '\x01';
  goto LAB_10015f80;
code_r0x1001601d:
  local_5a = '\0';
  FUN_100125f0(&local_50,&local_5a);
  uVar21 = FUN_10012320((undefined4 *)((int)this + 0x30));
  *(undefined4 *)((int)this + 0x28) = uVar21;
  goto LAB_10015f80;
}


// FUNCTION_END

// FUNCTION_START: FUN_100174f0 @ 100174f0