void __thiscall FUN_10014d80(void *this,uint *param_1)

{
  int iVar1;
  int *piVar2;
  byte bVar3;
  code *pcVar4;
  bool bVar5;
  char cVar6;
  uint *puVar7;
  uint uVar8;
  uint *puVar9;
  int *piVar10;
  void *pvVar11;
  int extraout_ECX;
  byte bVar12;
  uint uVar13;
  short sVar15;
  uint *puVar16;
  int iVar17;
  undefined2 in_SS;
  undefined8 uVar18;
  undefined1 *in_stack_ffffff08;
  undefined4 uVar19;
  undefined4 uVar20;
  void *local_dc [5];
  uint local_c8;
  undefined **local_c4;
  undefined **local_c0;
  undefined4 local_bc [2];
  undefined **local_b4;
  undefined **local_b0;
  undefined4 local_ac [2];
  void *local_a4 [4];
  undefined4 local_94;
  uint local_90;
  void *local_8c [4];
  undefined4 local_7c;
  uint local_78;
  void *local_74;
  uint uStack_70;
  uint uStack_6c;
  uint uStack_68;
  undefined8 local_64;
  uint *local_5c;
  char local_55;
  undefined1 local_54 [4];
  uint local_50;
  void *local_4c;
  undefined4 uStack_48;
  int iStack_44;
  uint uStack_40;
  int local_3c;
  undefined8 local_38;
  uint local_30;
  char local_2c [4];
  char local_28 [4];
  uint local_24;
  undefined1 *puStack_20;
  void *local_1c;
  undefined1 *puStack_18;
  undefined4 local_14;
  uint uVar14;
  
  puStack_20 = &stack0xfffffffc;
  puStack_18 = &LAB_1004f05e;
  local_1c = ExceptionList;
  local_24 = DAT_10069054 ^ (uint)&stack0xfffffff0;
  ExceptionList = &local_1c;
  local_5c = param_1;
  local_4c = (void *)0x0;
  uStack_48 = 0;
  iStack_44 = 0;
  uStack_40 = 0;
  local_14 = 0;
  local_55 = '\0';
  puVar7 = param_1;
LAB_10014df8:
  if (local_55 != '\0') {
    local_55 = '\0';
    goto LAB_1001505f;
  }
  switch(*(undefined4 *)((int)this + 0x28)) {
  case 1:
    uVar19 = FUN_10017ce0(puVar7);
    cVar6 = (char)uVar19;
    break;
  case 2:
    uVar19 = FUN_10017ce0(puVar7);
    cVar6 = (char)uVar19;
    goto joined_r0x10014e9e;
  case 3:
    uVar19 = FUN_10017d00(puVar7);
    cVar6 = (char)uVar19;
    goto joined_r0x10014e9e;
  case 4:
    uVar19 = FUN_10017c40(puVar7,(uint *)((int)this + 0x58));
    cVar6 = (char)uVar19;
    break;
  case 5:
    in_stack_ffffff08 = (undefined1 *)0x10015051;
    uVar19 = FUN_10017ca0(puVar7);
    cVar6 = (char)uVar19;
    break;
  case 6:
    in_stack_ffffff08 = (undefined1 *)0x1001501f;
    uVar19 = FUN_10017cc0(puVar7);
    cVar6 = (char)uVar19;
    break;
  case 7:
    bVar5 = FUN_10014d50();
    if (!bVar5) {
      puVar7 = (uint *)FUN_100121a0((void *)((int)this + 0x30),local_dc);
      local_14._0_1_ = 0xd;
      puVar7 = FUN_10005f20((uint *)local_8c,(uint *)"number overflow parsing \'",puVar7);
      local_14._0_1_ = 0xe;
      puVar7 = FUN_100055a0(puVar7,(uint *)&DAT_1005eec0);
      local_74 = (void *)*puVar7;
      uStack_70 = puVar7[1];
      uStack_6c = puVar7[2];
      uStack_68 = puVar7[3];
      local_64 = *(undefined8 *)(puVar7 + 4);
      puVar7[4] = 0;
      puVar7[5] = 0xf;
      *(undefined1 *)puVar7 = 0;
      local_14._0_1_ = 0xf;
      puVar7 = (uint *)FUN_1000af70(&local_c0,0x196,(uint *)&local_74);
      local_14._0_1_ = 0x10;
      uVar19 = 0x100154e2;
      FUN_100121a0((void *)((int)this + 0x30),local_a4);
      local_14 = CONCAT31(local_14._1_3_,0x11);
      uVar8 = FUN_100117c0(local_5c,in_stack_ffffff08,uVar19,(int)puVar7);
      local_55 = (char)uVar8;
      if (0xf < local_90) {
        pvVar11 = local_a4[0];
        if ((0xfff < local_90 + 1) &&
           (pvVar11 = *(void **)((int)local_a4[0] + -4),
           0x1f < (uint)((int)local_a4[0] + (-4 - (int)pvVar11)))) goto LAB_10015eb6;
        FUN_1002e346(pvVar11);
      }
      local_94 = 0;
      local_90 = 0xf;
      local_a4[0] = (void *)((uint)local_a4[0] & 0xffffff00);
      local_b0 = std::exception::vftable;
      ___std_exception_destroy(local_ac);
      local_c0 = std::exception::vftable;
      ___std_exception_destroy(local_bc);
      if (0xf < local_64._4_4_) {
        pvVar11 = local_74;
        if ((0xfff < local_64._4_4_ + 1) &&
           (pvVar11 = *(void **)((int)local_74 - 4),
           0x1f < (uint)((int)local_74 + (-4 - (int)pvVar11)))) goto LAB_10015eb6;
        FUN_1002e346(pvVar11);
      }
      if (0xf < local_78) {
        pvVar11 = local_8c[0];
        if ((0xfff < local_78 + 1) &&
           (pvVar11 = *(void **)((int)local_8c[0] + -4),
           0x1f < (uint)((int)local_8c[0] + (-4 - (int)pvVar11)))) goto LAB_10015eb6;
        FUN_1002e346(pvVar11);
      }
      local_7c = 0;
      local_78 = 0xf;
      local_8c[0] = (void *)((uint)local_8c[0] & 0xffffff00);
      goto joined_r0x100155f9;
    }
    cVar6 = FUN_10017c60(puVar7);
    break;
  case 8:
    local_3c = (int)(puVar7[2] - puVar7[1]) >> 2;
    local_28[0] = '\x02';
    if ((int *)puVar7[0x17] == (int *)0x0) goto LAB_10015ebb;
    local_2c[0] = (**(code **)(*(int *)puVar7[0x17] + 8))(&local_3c,local_28);
    FUN_100125f0(puVar7 + 4,local_2c);
    local_2c[0] = '\x02';
    in_stack_ffffff08 = (undefined1 *)((int)&local_38 + 4);
    FUN_100192b0(puVar7,in_stack_ffffff08,local_2c);
    puVar16 = (uint *)puVar7[2];
    if (puVar16 == (uint *)puVar7[3]) {
      in_stack_ffffff08 = (undefined1 *)0x10014f6d;
      FUN_1001a820(puVar7 + 1,puVar16,&local_30);
    }
    else {
      *puVar16 = local_30;
      puVar7[2] = puVar7[2] + 4;
    }
    iVar17 = FUN_10012320((undefined4 *)((int)this + 0x30));
    *(int *)((int)this + 0x28) = iVar17;
    if (iVar17 == 10) {
      uVar19 = FUN_100177a0((int)puVar7);
      cVar6 = (char)uVar19;
joined_r0x10014e9e:
      if (cVar6 != '\0') goto LAB_1001505f;
      goto LAB_10014ea4;
    }
    local_28[0] = '\x01';
    FUN_100125f0(&local_4c,local_28);
    goto LAB_10014df8;
  case 9:
    local_3c = (int)(puVar7[2] - puVar7[1]) >> 2;
    local_2c[0] = '\0';
    if ((int *)puVar7[0x17] == (int *)0x0) goto LAB_10015ebb;
    local_28[0] = (**(code **)(*(int *)puVar7[0x17] + 8))(&local_3c,local_2c);
    FUN_100125f0(puVar7 + 4,local_28);
    local_28[0] = '\x01';
    in_stack_ffffff08 = local_54;
    FUN_100192b0(puVar7,in_stack_ffffff08,local_28);
    puVar16 = (uint *)puVar7[2];
    if (puVar16 == (uint *)puVar7[3]) {
      in_stack_ffffff08 = (undefined1 *)0x10014e85;
      FUN_1001a820(puVar7 + 1,puVar16,&local_50);
    }
    else {
      *puVar16 = local_50;
      puVar7[2] = puVar7[2] + 4;
    }
    iVar17 = FUN_10012320((undefined4 *)((int)this + 0x30));
    *(int *)((int)this + 0x28) = iVar17;
    if (iVar17 == 0xb) {
      cVar6 = FUN_10017880((int)puVar7);
      goto joined_r0x10014e9e;
    }
    if (iVar17 == 4) {
      cVar6 = FUN_10017b00(puVar7,(uint *)((int)this + 0x58));
      if (cVar6 == '\0') goto LAB_10014ea4;
      iVar17 = FUN_10012320((undefined4 *)((int)this + 0x30));
      *(int *)((int)this + 0x28) = iVar17;
      if (iVar17 == 0xc) goto code_r0x10014ed9;
      local_64 = 0xf00000000;
      local_74 = (void *)0x0;
      FUN_10008e70(&local_74,(uint *)"object separator",0x10);
      local_14._0_1_ = 7;
      puVar7 = FUN_10011be0(local_a4,0xc,(uint *)&local_74);
      local_14._0_1_ = 8;
      local_30 = *(uint *)((int)this + 0x48);
      local_38 = *(undefined8 *)((int)this + 0x40);
      uVar19 = 0x100151de;
      puVar7 = (uint *)FUN_1000a5b0((undefined4 *)&local_38,puVar7);
      local_14._0_1_ = 9;
      uVar20 = 0x100151f3;
      FUN_100121a0((void *)((int)this + 0x30),local_8c);
      local_14 = CONCAT31(local_14._1_3_,10);
      uVar8 = FUN_100117c0(local_5c,uVar19,uVar20,(int)puVar7);
      local_55 = (char)uVar8;
      if (0xf < local_78) {
        pvVar11 = local_8c[0];
        if ((0xfff < local_78 + 1) &&
           (pvVar11 = *(void **)((int)local_8c[0] + -4),
           0x1f < (uint)((int)local_8c[0] + (-4 - (int)pvVar11)))) goto LAB_10015eb6;
        FUN_1002e346(pvVar11);
      }
      local_7c = 0;
      local_78 = 0xf;
      local_8c[0] = (void *)((uint)local_8c[0] & 0xffffff00);
      local_b4 = std::exception::vftable;
      ___std_exception_destroy(&local_b0);
      local_c4 = std::exception::vftable;
      ___std_exception_destroy(&local_c0);
      if (0xf < local_90) {
        pvVar11 = local_a4[0];
        if ((0xfff < local_90 + 1) &&
           (pvVar11 = *(void **)((int)local_a4[0] + -4),
           0x1f < (uint)((int)local_a4[0] + (-4 - (int)pvVar11)))) goto LAB_10015eb6;
        FUN_1002e346(pvVar11);
      }
      local_94 = 0;
      local_90 = 0xf;
      local_a4[0] = (void *)((uint)local_a4[0] & 0xffffff00);
LAB_100152cd:
      local_dc[0] = local_74;
      local_c8 = local_64._4_4_;
joined_r0x100155f9:
      if (0xf < local_c8) {
        pvVar11 = local_dc[0];
        if ((0xfff < local_c8 + 1) &&
           (pvVar11 = *(void **)((int)local_dc[0] - 4),
           0x1f < (uint)((int)local_dc[0] + (-4 - (int)pvVar11)))) goto LAB_10015eb6;
LAB_10015e50:
        FUN_1002e346(pvVar11);
      }
LAB_10015e60:
      if (local_4c != (void *)0x0) {
        pvVar11 = local_4c;
        if ((0xfff < (iStack_44 - (int)local_4c & 0xfffffffcU)) &&
           (pvVar11 = *(void **)((int)local_4c + -4),
           0x1f < (uint)((int)local_4c + (-4 - (int)pvVar11)))) {
LAB_10015eb6:
          FUN_10032f7f();
LAB_10015ebb:
          uVar18 = FUN_1002c837();
          uVar13 = (uint)((ulonglong)uVar18 >> 0x20);
          puVar9 = (uint *)uVar18;
          *(int *)((int)this + 1) = *(int *)((int)this + 1) + -1;
          *puVar9 = *puVar9 + uVar13;
          out((short)((ulonglong)uVar18 >> 0x20),(char)uVar18);
          iVar17 = (int)this + -2;
          *puVar9 = *puVar9 + uVar13;
          puVar16 = (uint *)((int)puVar9 + 1);
          uVar8 = *puVar16;
          *puVar16 = *puVar16 - uVar13;
          *(char *)puVar7 = (char)*puVar7 + (char)((uint)&stack0xfffffffc >> 8) + (uVar8 < uVar13);
          uVar8 = *puVar9;
          *puVar9 = *puVar9 + uVar13;
          bVar12 = (byte)((ulonglong)uVar18 >> 0x20);
          bVar3 = bVar12 + *(byte *)((int)puVar9 + 1);
          uVar14 = CONCAT31((int3)((ulonglong)uVar18 >> 0x28),bVar3 + CARRY4(uVar8,uVar13));
          *(char *)(extraout_ECX + -0x3effeb1) =
               *(char *)(extraout_ECX + -0x3effeb1) + (char)((uint)extraout_ECX >> 8) +
               (CARRY1(bVar12,*(byte *)((int)puVar9 + 1)) || CARRY1(bVar3,CARRY4(uVar8,uVar13)));
          uVar8 = *puVar9;
          *puVar9 = *puVar9 + uVar14;
          piVar10 = (int *)CONCAT31((int3)((ulonglong)uVar18 >> 8),
                                    (char)uVar18 + 'N' + CARRY4(uVar8,uVar14));
          *piVar10 = *piVar10 + uVar14;
          sVar15 = (short)&stack0xffffff10;
          piVar2 = (int *)segment(in_SS,sVar15 + -4);
          *piVar2 = iVar17;
          *piVar10 = *piVar10 + uVar14;
          piVar2 = (int *)segment(in_SS,sVar15 + -8);
          *piVar2 = iVar17;
          *piVar10 = *piVar10 + uVar14;
          piVar2 = (int *)segment(in_SS,sVar15 + -0xc);
          *piVar2 = iVar17;
          *piVar10 = *piVar10 + uVar14;
          piVar2 = (int *)segment(in_SS,sVar15 + -0x10);
          *piVar2 = iVar17;
          *piVar10 = *piVar10 + uVar14;
          pcVar4 = (code *)swi(3);
          (*pcVar4)();
          return;
        }
        FUN_1002e346(pvVar11);
      }
      ExceptionList = local_1c;
      FUN_1002e315(local_24 ^ (uint)&stack0xfffffff0);
      return;
    }
    local_64 = 0xf00000000;
    local_74 = (void *)0x0;
    FUN_10008e70(&local_74,(uint *)"object key",10);
    local_14._0_1_ = 3;
    puVar7 = FUN_10011be0(local_8c,4,(uint *)&local_74);
    local_14._0_1_ = 4;
    local_30 = *(uint *)((int)this + 0x48);
    local_38 = *(undefined8 *)((int)this + 0x40);
    uVar19 = 0x10015365;
    puVar7 = (uint *)FUN_1000a5b0((undefined4 *)&local_38,puVar7);
    local_14._0_1_ = 5;
    uVar20 = 0x1001537d;
    FUN_100121a0((void *)((int)this + 0x30),local_a4);
    local_14 = CONCAT31(local_14._1_3_,6);
    uVar8 = FUN_100117c0(local_5c,uVar19,uVar20,(int)puVar7);
    local_55 = (char)uVar8;
    if (0xf < local_90) {
      pvVar11 = local_a4[0];
      if ((0xfff < local_90 + 1) &&
         (pvVar11 = *(void **)((int)local_a4[0] + -4),
         0x1f < (uint)((int)local_a4[0] + (-4 - (int)pvVar11)))) goto LAB_10015eb6;
      FUN_1002e346(pvVar11);
    }
    local_94 = 0;
    local_90 = 0xf;
    local_a4[0] = (void *)((uint)local_a4[0] & 0xffffff00);
    local_b4 = std::exception::vftable;
    ___std_exception_destroy(&local_b0);
    local_c4 = std::exception::vftable;
    ___std_exception_destroy(&local_c0);
    if (local_78 < 0x10) goto LAB_10015445;
    pvVar11 = local_8c[0];
    if ((0xfff < local_78 + 1) &&
       (pvVar11 = *(void **)((int)local_8c[0] + -4),
       0x1f < (uint)((int)local_8c[0] + (-4 - (int)pvVar11)))) goto LAB_10015eb6;
    FUN_1002e346(pvVar11);
    goto LAB_10015445;
  default:
    local_64 = 0xf00000000;
    local_74 = (void *)0x0;
    FUN_10008e70(&local_74,(uint *)"value",5);
    local_14._0_1_ = 0x16;
    puVar7 = FUN_10011be0(local_8c,0x10,(uint *)&local_74);
    local_14._0_1_ = 0x17;
    local_30 = *(uint *)((int)this + 0x48);
    local_38 = *(undefined8 *)((int)this + 0x40);
    uVar19 = 0x100157c8;
    puVar7 = (uint *)FUN_1000a5b0((undefined4 *)&local_38,puVar7);
    local_14._0_1_ = 0x18;
    uVar20 = 0x100157e0;
    FUN_100121a0((void *)((int)this + 0x30),local_a4);
    local_14 = CONCAT31(local_14._1_3_,0x19);
    uVar8 = FUN_100117c0(local_5c,uVar19,uVar20,(int)puVar7);
    local_55 = (char)uVar8;
    if (0xf < local_90) {
      pvVar11 = local_a4[0];
      if ((0xfff < local_90 + 1) &&
         (pvVar11 = *(void **)((int)local_a4[0] + -4),
         0x1f < (uint)((int)local_a4[0] + (-4 - (int)pvVar11)))) goto LAB_10015eb6;
      FUN_1002e346(pvVar11);
    }
    local_94 = 0;
    local_90 = 0xf;
    local_a4[0] = (void *)((uint)local_a4[0] & 0xffffff00);
    local_b4 = std::exception::vftable;
    ___std_exception_destroy(&local_b0);
    local_c4 = std::exception::vftable;
    ___std_exception_destroy(&local_c0);
    if (local_78 < 0x10) goto LAB_10015445;
    pvVar11 = local_8c[0];
    if ((0xfff < local_78 + 1) &&
       (pvVar11 = *(void **)((int)local_8c[0] + -4),
       0x1f < (uint)((int)local_8c[0] + (-4 - (int)pvVar11)))) goto LAB_10015eb6;
    FUN_1002e346(pvVar11);
    local_7c = 0;
    local_78 = 0xf;
    local_8c[0] = (void *)((uint)local_8c[0] & 0xffffff00);
    goto LAB_100152cd;
  case 0xe:
    local_64 = 0xf00000000;
    local_74 = (void *)0x0;
    FUN_10008e70(&local_74,(uint *)"value",5);
    local_14._0_1_ = 0x12;
    puVar7 = FUN_10011be0(local_8c,0,(uint *)&local_74);
    local_14._0_1_ = 0x13;
    local_30 = *(uint *)((int)this + 0x48);
    local_38 = *(undefined8 *)((int)this + 0x40);
    uVar19 = 0x1001566c;
    puVar7 = (uint *)FUN_1000a5b0((undefined4 *)&local_38,puVar7);
    local_14._0_1_ = 0x14;
    uVar20 = 0x10015684;
    FUN_100121a0((void *)((int)this + 0x30),local_a4);
    local_14 = CONCAT31(local_14._1_3_,0x15);
    uVar8 = FUN_100117c0(local_5c,uVar19,uVar20,(int)puVar7);
    local_55 = (char)uVar8;
    if (0xf < local_90) {
      pvVar11 = local_a4[0];
      if ((0xfff < local_90 + 1) &&
         (pvVar11 = *(void **)((int)local_a4[0] + -4),
         0x1f < (uint)((int)local_a4[0] + (-4 - (int)pvVar11)))) goto LAB_10015eb6;
      FUN_1002e346(pvVar11);
    }
    local_94 = 0;
    local_90 = 0xf;
    local_a4[0] = (void *)((uint)local_a4[0] & 0xffffff00);
    local_b4 = std::exception::vftable;
    ___std_exception_destroy(&local_b0);
    local_c4 = std::exception::vftable;
    ___std_exception_destroy(&local_c0);
    if (local_78 < 0x10) goto LAB_10015445;
    pvVar11 = local_8c[0];
    if ((0xfff < local_78 + 1) &&
       (pvVar11 = *(void **)((int)local_8c[0] + -4),
       0x1f < (uint)((int)local_8c[0] + (-4 - (int)pvVar11)))) goto LAB_10015eb6;
    FUN_1002e346(pvVar11);
    local_7c = 0;
    local_78 = 0xf;
    local_8c[0] = (void *)((uint)local_8c[0] & 0xffffff00);
    goto LAB_100152cd;
  }
  if (cVar6 == '\0') {
LAB_10014ea4:
    local_55 = '\0';
    goto LAB_10015e60;
  }
LAB_1001505f:
  if (uStack_40 == 0) {
    local_55 = '\x01';
    goto LAB_10015e60;
  }
  if (((int)uStack_40 < 0) && (uStack_40 != 0)) {
    iVar17 = -((~uStack_40 >> 5) * 4 + 4);
  }
  else {
    iVar17 = (uStack_40 >> 5) * 4;
  }
  uVar8 = (uStack_40 & 0x1f) - 1;
  if ((uStack_40 & 0x1f) == 0) {
    iVar1 = -((~uVar8 >> 5) * 4 + 4);
  }
  else {
    iVar1 = (uVar8 >> 5) * 4;
  }
  puVar7 = (uint *)((int)local_4c + iVar1 + iVar17);
  if ((*puVar7 & 1 << ((byte)uVar8 & 0x1f)) == 0) {
    iVar17 = FUN_10012320((undefined4 *)((int)this + 0x30));
    puVar16 = local_5c;
    *(int *)((int)this + 0x28) = iVar17;
    if (iVar17 != 0xd) {
      if (iVar17 != 0xb) {
        local_64 = 0xf00000000;
        local_74 = (void *)0x0;
        FUN_10008e70(&local_74,(uint *)"object",6);
        local_14._0_1_ = 0x26;
        puVar7 = FUN_10011be0(local_8c,0xb,(uint *)&local_74);
        local_14._0_1_ = 0x27;
        local_30 = *(uint *)((int)this + 0x48);
        local_38 = *(undefined8 *)((int)this + 0x40);
        uVar19 = 0x10015d38;
        puVar7 = (uint *)FUN_1000a5b0((undefined4 *)&local_38,puVar7);
        local_14._0_1_ = 0x28;
        uVar20 = 0x10015d50;
        FUN_100121a0((void *)((int)this + 0x30),local_a4);
        local_14 = CONCAT31(local_14._1_3_,0x29);
        uVar8 = FUN_100117c0(local_5c,uVar19,uVar20,(int)puVar7);
        local_55 = (char)uVar8;
        if (0xf < local_90) {
          pvVar11 = local_a4[0];
          if ((0xfff < local_90 + 1) &&
             (pvVar11 = *(void **)((int)local_a4[0] + -4),
             0x1f < (uint)((int)local_a4[0] + (-4 - (int)pvVar11)))) goto LAB_10015eb6;
          FUN_1002e346(pvVar11);
        }
        local_94 = 0;
        local_90 = 0xf;
        local_a4[0] = (void *)((uint)local_a4[0] & 0xffffff00);
        local_b4 = std::exception::vftable;
        ___std_exception_destroy(&local_b0);
        local_c4 = std::exception::vftable;
        ___std_exception_destroy(&local_c0);
        if (0xf < local_78) {
          pvVar11 = local_8c[0];
          if ((0xfff < local_78 + 1) &&
             (pvVar11 = *(void **)((int)local_8c[0] + -4),
             0x1f < (uint)((int)local_8c[0] + (-4 - (int)pvVar11)))) goto LAB_10015eb6;
          FUN_1002e346(pvVar11);
        }
        local_7c = 0;
        local_78 = 0xf;
        local_8c[0] = (void *)((uint)local_8c[0] & 0xffffff00);
        if (local_64._4_4_ < 0x10) goto LAB_10015e60;
        pvVar11 = local_74;
        if ((local_64._4_4_ + 1 < 0x1000) ||
           (pvVar11 = *(void **)((int)local_74 - 4),
           (uint)((int)local_74 + (-4 - (int)pvVar11)) < 0x20)) goto LAB_10015e50;
        goto LAB_10015eb6;
      }
      cVar6 = FUN_10017880((int)local_5c);
LAB_100150e9:
      puVar7 = puVar16;
      if (cVar6 == '\0') goto LAB_10014ea4;
      FUN_10017fb0((int *)&local_4c);
      local_55 = '\x01';
      goto LAB_10014df8;
    }
    iVar17 = FUN_10012320((undefined4 *)((int)this + 0x30));
    *(int *)((int)this + 0x28) = iVar17;
    if (iVar17 == 4) {
      cVar6 = FUN_10017b00(local_5c,(uint *)((int)this + 0x58));
      if (cVar6 == '\0') goto LAB_10014ea4;
      iVar17 = FUN_10012320((undefined4 *)((int)this + 0x30));
      *(int *)((int)this + 0x28) = iVar17;
      if (iVar17 == 0xc) goto LAB_1001514c;
      local_64 = 0xf00000000;
      local_74 = (void *)0x0;
      FUN_10008e70(&local_74,(uint *)"object separator",0x10);
      local_14._0_1_ = 0x22;
      puVar7 = FUN_10011be0(local_8c,0xc,(uint *)&local_74);
      local_14._0_1_ = 0x23;
      local_30 = *(uint *)((int)this + 0x48);
      local_38 = *(undefined8 *)((int)this + 0x40);
      uVar19 = 0x10015a80;
      puVar7 = (uint *)FUN_1000a5b0((undefined4 *)&local_38,puVar7);
      local_14._0_1_ = 0x24;
      uVar20 = 0x10015a98;
      FUN_100121a0((void *)((int)this + 0x30),local_a4);
      local_14 = CONCAT31(local_14._1_3_,0x25);
      uVar8 = FUN_100117c0(local_5c,uVar19,uVar20,(int)puVar7);
      local_55 = (char)uVar8;
      if (0xf < local_90) {
        pvVar11 = local_a4[0];
        if ((0xfff < local_90 + 1) &&
           (pvVar11 = *(void **)((int)local_a4[0] + -4),
           0x1f < (uint)((int)local_a4[0] + (-4 - (int)pvVar11)))) goto LAB_10015eb6;
        FUN_1002e346(pvVar11);
      }
      local_94 = 0;
      local_90 = 0xf;
      local_a4[0] = (void *)((uint)local_a4[0] & 0xffffff00);
      local_b4 = std::exception::vftable;
      ___std_exception_destroy(&local_b0);
      local_c4 = std::exception::vftable;
      ___std_exception_destroy(&local_c0);
      if (0xf < local_78) {
        pvVar11 = local_8c[0];
        if ((0xfff < local_78 + 1) &&
           (pvVar11 = *(void **)((int)local_8c[0] + -4),
           0x1f < (uint)((int)local_8c[0] + (-4 - (int)pvVar11)))) goto LAB_10015eb6;
        FUN_1002e346(pvVar11);
        local_7c = 0;
        local_78 = 0xf;
        local_8c[0] = (void *)((uint)local_8c[0] & 0xffffff00);
        goto LAB_100152cd;
      }
    }
    else {
      local_64 = 0xf00000000;
      local_74 = (void *)0x0;
      FUN_10008e70(&local_74,(uint *)"object key",10);
      local_14._0_1_ = 0x1e;
      puVar7 = FUN_10011be0(local_8c,4,(uint *)&local_74);
      local_14._0_1_ = 0x1f;
      local_30 = *(uint *)((int)this + 0x48);
      local_38 = *(undefined8 *)((int)this + 0x40);
      uVar19 = 0x10015bdc;
      puVar7 = (uint *)FUN_1000a5b0((undefined4 *)&local_38,puVar7);
      local_14._0_1_ = 0x20;
      uVar20 = 0x10015bf4;
      FUN_100121a0((void *)((int)this + 0x30),local_a4);
      local_14 = CONCAT31(local_14._1_3_,0x21);
      uVar8 = FUN_100117c0(local_5c,uVar19,uVar20,(int)puVar7);
      local_55 = (char)uVar8;
      if (0xf < local_90) {
        pvVar11 = local_a4[0];
        if ((0xfff < local_90 + 1) &&
           (pvVar11 = *(void **)((int)local_a4[0] + -4),
           0x1f < (uint)((int)local_a4[0] + (-4 - (int)pvVar11)))) goto LAB_10015eb6;
        FUN_1002e346(pvVar11);
      }
      local_94 = 0;
      local_90 = 0xf;
      local_a4[0] = (void *)((uint)local_a4[0] & 0xffffff00);
      local_b4 = std::exception::vftable;
      ___std_exception_destroy(&local_b0);
      local_c4 = std::exception::vftable;
      ___std_exception_destroy(&local_c0);
      if (0xf < local_78) {
        pvVar11 = local_8c[0];
        if ((0xfff < local_78 + 1) &&
           (pvVar11 = *(void **)((int)local_8c[0] + -4),
           0x1f < (uint)((int)local_8c[0] + (-4 - (int)pvVar11)))) goto LAB_10015eb6;
        FUN_1002e346(pvVar11);
        local_7c = 0;
        local_78 = 0xf;
        local_8c[0] = (void *)((uint)local_8c[0] & 0xffffff00);
        goto LAB_100152cd;
      }
    }
  }
  else {
    iVar17 = FUN_10012320((undefined4 *)((int)this + 0x30));
    puVar16 = local_5c;
    *(int *)((int)this + 0x28) = iVar17;
    if (iVar17 == 0xd) {
LAB_1001514c:
      uVar19 = FUN_10012320((undefined4 *)((int)this + 0x30));
      *(undefined4 *)((int)this + 0x28) = uVar19;
      puVar7 = local_5c;
      goto LAB_10014df8;
    }
    if (iVar17 == 10) {
      uVar19 = FUN_100177a0((int)local_5c);
      cVar6 = (char)uVar19;
      goto LAB_100150e9;
    }
    local_64 = 0xf00000000;
    local_74 = (void *)0x0;
    FUN_10008e70(&local_74,(uint *)"array",5);
    local_14._0_1_ = 0x1a;
    puVar7 = FUN_10011be0(local_8c,10,(uint *)&local_74);
    local_14._0_1_ = 0x1b;
    local_30 = *(uint *)((int)this + 0x48);
    local_38 = *(undefined8 *)((int)this + 0x40);
    uVar19 = 0x10015924;
    puVar7 = (uint *)FUN_1000a5b0((undefined4 *)&local_38,puVar7);
    local_14._0_1_ = 0x1c;
    uVar20 = 0x1001593c;
    FUN_100121a0((void *)((int)this + 0x30),local_a4);
    local_14 = CONCAT31(local_14._1_3_,0x1d);
    uVar8 = FUN_100117c0(local_5c,uVar19,uVar20,(int)puVar7);
    local_55 = (char)uVar8;
    if (0xf < local_90) {
      pvVar11 = local_a4[0];
      if ((0xfff < local_90 + 1) &&
         (pvVar11 = *(void **)((int)local_a4[0] + -4),
         0x1f < (uint)((int)local_a4[0] + (-4 - (int)pvVar11)))) goto LAB_10015eb6;
      FUN_1002e346(pvVar11);
    }
    local_94 = 0;
    local_90 = 0xf;
    local_a4[0] = (void *)((uint)local_a4[0] & 0xffffff00);
    local_b4 = std::exception::vftable;
    ___std_exception_destroy(&local_b0);
    local_c4 = std::exception::vftable;
    ___std_exception_destroy(&local_c0);
    if (0xf < local_78) {
      pvVar11 = local_8c[0];
      if ((0xfff < local_78 + 1) &&
         (pvVar11 = *(void **)((int)local_8c[0] + -4),
         0x1f < (uint)((int)local_8c[0] + (-4 - (int)pvVar11)))) goto LAB_10015eb6;
      FUN_1002e346(pvVar11);
      local_7c = 0;
      local_78 = 0xf;
      local_8c[0] = (void *)((uint)local_8c[0] & 0xffffff00);
      goto LAB_100152cd;
    }
  }
LAB_10015445:
  local_7c = 0;
  local_78 = 0xf;
  local_8c[0] = (void *)((uint)local_8c[0] & 0xffffff00);
  goto LAB_100152cd;
code_r0x10014ed9:
  local_28[0] = '\0';
  FUN_100125f0(&local_4c,local_28);
  uVar19 = FUN_10012320((undefined4 *)((int)this + 0x30));
  *(undefined4 *)((int)this + 0x28) = uVar19;
  goto LAB_10014df8;
}


// FUNCTION_END

// FUNCTION_START: FUN_10015f00 @ 10015f00

/* WARNING: Instruction at (ram,0x10017552) overlaps instruction at (ram,0x10017550)
    */
/* WARNING (jumptable): Unable to track spacebase fully for stack */
/* WARNING: Unable to track spacebase fully for stack */