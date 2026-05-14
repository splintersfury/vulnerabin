void __thiscall FUN_100109e0(void *this,undefined4 param_1,char *param_2)

{
  code *pcVar1;
  undefined3 uVar2;
  undefined1 uVar3;
  uint uVar4;
  int iVar5;
  uint *puVar6;
  void *pvVar7;
  char *pcVar8;
  undefined4 uVar9;
  undefined4 uVar10;
  char cVar11;
  int local_150 [2];
  undefined **local_148;
  undefined4 local_144 [3];
  undefined **local_138;
  undefined4 local_134 [2];
  int *local_12c;
  undefined **local_124;
  undefined4 local_120;
  void *local_11c [2];
  undefined **local_114;
  undefined4 local_110;
  undefined4 local_10c;
  uint local_108;
  void *local_104 [4];
  undefined4 local_f4;
  uint local_f0;
  void *local_ec [4];
  undefined4 local_dc;
  uint local_d8;
  int *local_d4;
  char local_d0 [4];
  undefined8 local_cc;
  undefined4 local_c4;
  byte local_b9;
  char *local_b8;
  undefined4 local_b4;
  undefined4 local_b0;
  undefined4 local_ac;
  undefined4 local_a8;
  undefined4 uStack_a4;
  undefined4 uStack_a0;
  undefined4 uStack_9c;
  undefined4 local_98;
  undefined4 uStack_94;
  undefined4 uStack_90;
  undefined4 uStack_8c;
  undefined4 local_88;
  char local_84;
  undefined1 local_80 [36];
  undefined4 local_5c;
  byte local_58;
  undefined1 local_50;
  undefined1 local_48 [12];
  char *local_3c;
  void *pvStack_38;
  undefined4 uStack_34;
  int iStack_30;
  undefined8 local_2c;
  uint local_24;
  undefined1 *puStack_20;
  void *local_1c;
  undefined1 *puStack_18;
  undefined4 local_14;
  
  puStack_20 = &stack0xfffffffc;
  local_14 = 0xffffffff;
  puStack_18 = &LAB_1004ebaf;
  local_1c = ExceptionList;
  uVar4 = DAT_10069054 ^ (uint)&stack0xfffffff0;
  ExceptionList = &local_1c;
  local_b9 = *(byte *)((int)this + 0x98);
  local_24 = uVar4;
  if (*(int *)((int)this + 0x24) == 0) {
    local_3c = param_2;
    pvStack_38 = (void *)0x0;
    uStack_34 = 0;
    iStack_30 = 0;
    local_2c = (ulonglong)local_b9 << 0x28;
    local_14._0_1_ = 0xe;
    local_14._1_3_ = 0;
    FUN_10015f00(this,&local_3c);
    local_d4 = (int *)((int)this + 0x30);
    iVar5 = FUN_10012320(local_d4);
    *(int *)((int)this + 0x28) = iVar5;
    if (iVar5 != 0xf) {
      local_dc = 0;
      local_d8 = 0xf;
      local_ec[0] = (void *)0x0;
      FUN_10008e70(local_ec,(uint *)"value",5);
      local_14._0_1_ = 0xf;
      puVar6 = FUN_10011be0(local_11c,0xf,(uint *)local_ec);
      local_14._0_1_ = 0x10;
      local_c4 = *(undefined4 *)((int)this + 0x48);
      local_cc = *(undefined8 *)((int)this + 0x40);
      uVar9 = 0x10010e7b;
      iVar5 = FUN_1000a5b0((undefined4 *)&local_cc,puVar6);
      local_14._0_1_ = 0x11;
      uVar10 = 0x10010e96;
      FUN_100121a0(local_d4,local_104);
      local_14._0_1_ = 0x12;
      FUN_10011680(&local_3c,uVar9,uVar10,iVar5);
      local_14._0_1_ = 0x11;
      if (0xf < local_f0) {
        pvVar7 = local_104[0];
        if ((0xfff < local_f0 + 1) &&
           (pvVar7 = *(void **)((int)local_104[0] + -4),
           0x1f < (uint)((int)local_104[0] + (-4 - (int)pvVar7)))) goto LAB_100110ab;
        FUN_1002e346(pvVar7);
      }
      local_f4 = 0;
      local_f0 = 0xf;
      local_104[0] = (void *)((uint)local_104[0] & 0xffffff00);
      local_138 = std::exception::vftable;
      ___std_exception_destroy(local_134);
      local_148 = std::exception::vftable;
      ___std_exception_destroy(local_144);
      local_14._0_1_ = 0xf;
      if (0xf < local_108) {
        pvVar7 = local_11c[0];
        if ((0xfff < local_108 + 1) &&
           (pvVar7 = *(void **)((int)local_11c[0] + -4),
           0x1f < (uint)((int)local_11c[0] + (-4 - (int)pvVar7)))) goto LAB_100110ab;
        FUN_1002e346(pvVar7);
      }
      local_14._0_1_ = 0xe;
      local_10c = 0;
      local_108 = 0xf;
      local_11c[0] = (void *)((uint)local_11c[0] & 0xffffff00);
      if (0xf < local_d8) {
        pvVar7 = local_ec[0];
        if ((0xfff < local_d8 + 1) &&
           (pvVar7 = *(void **)((int)local_ec[0] + -4),
           0x1f < (uint)((int)local_ec[0] + (-4 - (int)pvVar7)))) goto LAB_100110ab;
        FUN_1002e346(pvVar7);
      }
    }
    if (local_2c._4_1_ == '\0') {
      if (pvStack_38 == (void *)0x0) goto LAB_10011058;
      pvVar7 = pvStack_38;
      if (0xfff < (iStack_30 - (int)pvStack_38 & 0xfffffffcU)) {
        pvVar7 = *(void **)((int)pvStack_38 + -4);
        iVar5 = (int)pvStack_38 - (int)pvVar7;
        goto joined_r0x1001109f;
      }
    }
    else {
      local_d0[0] = '\b';
      FUN_1000f600((void *)((int)&local_cc + 4),'\b');
      cVar11 = *param_2;
      *param_2 = local_d0[0];
      uVar9 = *(undefined4 *)(param_2 + 0xc);
      uVar10 = *(undefined4 *)(param_2 + 8);
      *(undefined4 *)(param_2 + 0xc) = local_c4;
      *(undefined4 *)(param_2 + 8) = local_cc._4_4_;
      local_cc = CONCAT44(uVar10,(undefined4)local_cc);
      local_d0[0] = cVar11;
      local_c4 = uVar9;
      FUN_1000e760(local_d0);
      if (pvStack_38 == (void *)0x0) goto LAB_10011058;
      pvVar7 = pvStack_38;
      if (0xfff < (iStack_30 - (int)pvStack_38 & 0xfffffffcU)) {
        pvVar7 = *(void **)((int)pvStack_38 + -4);
        iVar5 = (int)pvStack_38 - (int)pvVar7;
joined_r0x1001109f:
        if (0x1f < iVar5 - 4U) {
          FUN_10032f7f();
          uVar3 = (undefined1)local_14;
          goto LAB_100110a6;
        }
      }
    }
    FUN_1002e346(pvVar7);
    goto LAB_10011058;
  }
  puStack_20 = &stack0xfffffffc;
  _memset(&local_b8,0,0x78);
  local_d4 = local_150;
  local_12c = (int *)0x0;
  local_14 = 0;
  local_12c = (int *)(**(code **)**(undefined4 **)((int)this + 0x24))(local_150,uVar4);
  local_b8 = param_2;
  local_b4 = 0;
  local_b0 = 0;
  local_ac = 0;
  local_a8 = 0;
  uStack_a4 = 0;
  uStack_a0 = 0;
  uStack_9c = 0;
  local_98 = 0;
  uStack_94 = 0;
  uStack_90 = 0;
  uStack_8c = 0;
  local_d4 = (int *)local_80;
  local_88 = 0;
  local_84 = '\0';
  local_5c = 0;
  local_14._1_3_ = 0;
  uVar2 = local_14._1_3_;
  local_14._0_1_ = 5;
  local_14._1_3_ = 0;
  if (local_12c != (int *)0x0) {
    local_5c = (**(code **)*local_12c)(local_80);
    uVar2 = local_14._1_3_;
  }
  local_14._1_3_ = uVar2;
  local_14._0_1_ = 6;
  local_58 = local_b9;
  local_50 = 8;
  FUN_1000f600(local_48,'\b');
  local_14 = CONCAT31(local_14._1_3_,7);
  local_b9 = 1;
  FUN_100125f0(&local_a8,(char *)&local_b9);
  if (local_12c != (int *)0x0) {
    (**(code **)(*local_12c + 0x10))(CONCAT31((int3)((uint)local_150 >> 8),local_12c != local_150));
    local_12c = (int *)0x0;
  }
  local_14._0_1_ = 8;
  local_14._1_3_ = 0;
  FUN_10014d80(this,(uint *)&local_b8);
  local_d4 = (int *)((int)this + 0x30);
  iVar5 = FUN_10012320(local_d4);
  *(int *)((int)this + 0x28) = iVar5;
  if (iVar5 != 0xf) {
    local_2c = 0xf00000000;
    local_3c = (char *)0x0;
    FUN_10008e70(&local_3c,(uint *)"value",5);
    local_14._0_1_ = 9;
    puVar6 = FUN_10011be0(local_104,0xf,(uint *)&local_3c);
    local_14._0_1_ = 10;
    local_c4 = *(undefined4 *)((int)this + 0x48);
    local_cc = *(undefined8 *)((int)this + 0x40);
    uVar9 = 0x10010bed;
    iVar5 = FUN_1000a5b0((undefined4 *)&local_cc,puVar6);
    local_14._0_1_ = 0xb;
    uVar10 = 0x10010c08;
    FUN_100121a0(local_d4,local_ec);
    local_14._0_1_ = 0xc;
    FUN_100117c0(&local_b8,uVar9,uVar10,iVar5);
    local_14._0_1_ = 0xb;
    uVar3 = (undefined1)local_14;
    local_14._0_1_ = 0xb;
    if (0xf < local_d8) {
      pvVar7 = local_ec[0];
      if ((local_d8 + 1 < 0x1000) ||
         (pvVar7 = *(void **)((int)local_ec[0] + -4),
         (uint)((int)local_ec[0] + (-4 - (int)pvVar7)) < 0x20)) {
        FUN_1002e346(pvVar7);
        goto LAB_10010c59;
      }
LAB_100110a6:
      local_14._0_1_ = uVar3;
      FUN_10032f7f();
LAB_100110ab:
      FUN_10032f7f();
      pcVar1 = (code *)swi(3);
      (*pcVar1)();
      return;
    }
LAB_10010c59:
    local_dc = 0;
    local_d8 = 0xf;
    local_ec[0] = (void *)((uint)local_ec[0] & 0xffffff00);
    local_114 = std::exception::vftable;
    ___std_exception_destroy(&local_110);
    local_124 = std::exception::vftable;
    ___std_exception_destroy(&local_120);
    local_14._0_1_ = 9;
    if (0xf < local_f0) {
      pvVar7 = local_104[0];
      if ((0xfff < local_f0 + 1) &&
         (pvVar7 = *(void **)((int)local_104[0] + -4), uVar3 = (undefined1)local_14,
         0x1f < (uint)((int)local_104[0] + (-4 - (int)pvVar7)))) goto LAB_100110a6;
      FUN_1002e346(pvVar7);
    }
    local_14._0_1_ = 8;
    local_f4 = 0;
    local_f0 = 0xf;
    local_104[0] = (void *)((uint)local_104[0] & 0xffffff00);
    if (0xf < local_2c._4_4_) {
      pcVar8 = local_3c;
      if ((0xfff < local_2c._4_4_ + 1) &&
         (pcVar8 = *(char **)(local_3c + -4), uVar3 = (undefined1)local_14,
         (char *)0x1f < local_3c + (-4 - (int)pcVar8))) goto LAB_100110a6;
      FUN_1002e346(pcVar8);
    }
  }
  if (local_84 == '\0') {
    if (*param_2 == '\b') {
      local_14._0_1_ = 0xd;
      local_d0[0] = '\0';
      cVar11 = '\0';
      goto LAB_10010d5a;
    }
  }
  else {
    local_d0[0] = '\b';
    cVar11 = '\b';
LAB_10010d5a:
    FUN_1000f600((void *)((int)&local_cc + 4),cVar11);
    cVar11 = *param_2;
    *param_2 = local_d0[0];
    uVar9 = *(undefined4 *)(param_2 + 8);
    uVar10 = *(undefined4 *)(param_2 + 0xc);
    *(undefined4 *)(param_2 + 8) = local_cc._4_4_;
    *(undefined4 *)(param_2 + 0xc) = local_c4;
    local_cc = CONCAT44(uVar9,(undefined4)local_cc);
    local_d0[0] = cVar11;
    local_c4 = uVar10;
    FUN_1000e760(local_d0);
  }
  FUN_10011510((int)&local_b8);
LAB_10011058:
  ExceptionList = local_1c;
  FUN_1002e315(local_24 ^ (uint)&stack0xfffffff0);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_100110c0 @ 100110c0