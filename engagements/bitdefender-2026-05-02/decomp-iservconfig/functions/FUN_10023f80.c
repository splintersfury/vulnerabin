void __fastcall FUN_10023f80(int param_1,int *param_2,int *param_3)

{
  undefined1 auVar1 [12];
  undefined1 auVar2 [16];
  undefined1 auVar3 [16];
  undefined4 uVar4;
  int iVar5;
  uint uVar6;
  uint uVar7;
  int in_XMM3_Da;
  uint in_XMM3_Db;
  uint local_80;
  int iStack_7c;
  undefined4 uStack_78;
  undefined4 uStack_74;
  int local_6c;
  int *local_68;
  int *local_64;
  undefined1 local_60 [8];
  undefined8 uStack_58;
  uint local_50;
  uint uStack_4c;
  int iStack_48;
  undefined4 uStack_44;
  uint local_40;
  uint uStack_3c;
  int iStack_38;
  undefined4 uStack_34;
  undefined8 local_30;
  int iStack_28;
  undefined4 uStack_24;
  undefined1 local_20 [16];
  uint local_c;
  
  auVar2 = local_20;
  local_c = DAT_10069054 ^ (uint)&stack0xfffffffc;
  local_64 = param_3;
  uVar7 = in_XMM3_Db >> 0x14;
  if (uVar7 == 0) {
    local_20._0_8_ = CONCAT44(in_XMM3_Db,in_XMM3_Da) & 0xfffffffffffff;
    local_20._8_4_ = 0xfffffbce;
  }
  else {
    local_20._4_4_ = (in_XMM3_Db & 0xfffff) + 0x100000;
    local_20._0_4_ = in_XMM3_Da;
    local_20._8_4_ = uVar7 - 0x433;
  }
  auVar3 = local_20;
  uVar4 = uStack_58._4_4_;
  if ((in_XMM3_Da == 0 && (in_XMM3_Db & 0xfffff) == 0) && (1 < uVar7)) {
    iVar5 = local_20._8_4_ + -2;
    uStack_4c = (local_20._4_4_ << 1 | (uint)local_20._0_4_ >> 0x1f) +
                (uint)(0xfffffffe < (uint)(local_20._0_4_ * 2));
    uVar6 = local_20._4_4_ << 2 | (uint)local_20._0_4_ >> 0x1e;
    uVar7 = local_20._0_4_ * 4;
  }
  else {
    uVar6 = local_20._4_4_ << 1 | (uint)local_20._0_4_ >> 0x1f;
    uVar7 = local_20._0_4_ * 2;
    uStack_4c = uVar6 + (0xfffffffe < uVar7);
    iVar5 = local_20._8_4_ + -1;
  }
  local_50 = uVar7 - 1;
  iStack_48 = local_20._8_4_ + -1;
  local_30 = CONCAT44((uVar6 - 1) + (uint)(uVar7 != 0),local_50);
  uStack_44 = uStack_58._4_4_;
  local_50 = local_20._0_4_ * 2 + 1;
  do {
    do {
      uStack_4c = uStack_4c << 1 | local_50 >> 0x1f;
      iStack_48 = iStack_48 + -1;
      local_50 = local_50 * 2;
    } while (0 < (int)uStack_4c);
  } while (-1 < (int)uStack_4c);
  local_30 = local_30 << (ulonglong)(uint)(iVar5 - iStack_48);
  _local_60 = auVar3;
  if ((auVar2 & (undefined1  [16])0x8000000000000000) == (undefined1  [16])0x0) {
    do {
      do {
        auVar3 = _local_60;
        local_20._4_4_ = local_20._4_4_ << 1 | (uint)local_20._0_4_ >> 0x1f;
        local_20._8_4_ = local_20._8_4_ + -1;
        local_20._0_4_ = local_20._0_4_ * 2;
        auVar1._4_8_ = uStack_58;
        auVar1._0_4_ = local_20._4_4_;
        auVar2._12_4_ = 0;
        auVar2._0_12_ = auVar1;
        _local_60 = auVar2 << 0x20;
      } while (0 < (int)local_20._4_4_);
    } while (-1 < (int)local_20._4_4_);
    stack0xffffffa4 = auVar1;
    local_60._0_4_ = local_20._0_4_;
    auVar2 = _local_60;
    uStack_58._4_4_ = auVar3._12_4_;
    local_60 = auVar2._0_8_;
    uStack_58._0_4_ = local_20._8_4_;
  }
  iVar5 = (-0x3d - iStack_48) * 0x13441;
  _iStack_38 = CONCAT44(uVar4,iStack_48);
  iVar5 = ((int)(iVar5 + (iVar5 >> 0x1f & 0x3ffffU)) >> 0x12) + (0 < -0x3d - iStack_48) + 0x133;
  uStack_24 = local_20._12_4_;
  iVar5 = ((int)((iVar5 >> 0x1f & 7U) + iVar5) >> 3) * 0x10;
  local_6c = param_1;
  local_68 = param_2;
  local_40 = local_50;
  uStack_3c = uStack_4c;
  iStack_28 = iStack_48;
  local_20 = _local_60;
  _local_60 = *(undefined1 (*) [12])(&DAT_100606b0 + iVar5);
  FUN_1001c8f0((int *)&local_80,(uint *)local_20,(uint *)local_60);
  FUN_1001c8f0((int *)local_20,(uint *)&local_30,(uint *)local_60);
  FUN_1001c8f0((int *)&local_50,&local_40,(uint *)local_60);
  auVar2 = local_20;
  local_60._0_4_ = local_20._0_4_ + 1;
  local_60._4_4_ = local_20._4_4_ + (uint)(0xfffffffe < (uint)local_20._0_4_);
  uVar4 = local_20._8_4_;
  uStack_58._0_4_ = local_20._8_4_;
  local_20._4_4_ = (uStack_4c - 1) + (uint)(local_50 != 0);
  local_20._0_4_ = local_50 - 1;
  local_20._12_4_ = auVar2._12_4_;
  local_20._8_4_ = iStack_48;
  *local_64 = -*(int *)(&UNK_100606bc + iVar5);
  FUN_1001ca50(local_6c,local_68,local_64,local_60._0_4_,local_60._4_4_,uVar4,uStack_58._4_4_,
               local_80,iStack_7c,uStack_78,uStack_74,local_50 - 1,local_20._4_4_,iStack_48);
  FUN_1002e315(local_c ^ (uint)&stack0xfffffffc);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_10024240 @ 10024240