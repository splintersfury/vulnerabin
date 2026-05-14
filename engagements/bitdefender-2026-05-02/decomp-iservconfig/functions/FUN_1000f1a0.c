void __thiscall FUN_1000f1a0(void *this,uint *param_1)

{
  int *piVar1;
  wchar_t *pwVar2;
  undefined4 *puVar3;
  uint uVar4;
  undefined4 local_160 [8];
  undefined4 local_140;
  undefined **local_13c;
  uint local_138;
  uint uStack_134;
  uint uStack_130;
  uint uStack_12c;
  undefined8 local_128;
  uint local_120;
  uint local_11c;
  uint local_118;
  uint uStack_114;
  uint uStack_110;
  uint uStack_10c;
  undefined4 local_108;
  int aiStack_104 [4];
  byte abStack_f4 [4];
  int local_f0 [10];
  undefined4 auStack_c8 [9];
  int local_a4;
  undefined **local_90 [19];
  uint local_44;
  uint uStack_40;
  uint uStack_3c;
  uint uStack_38;
  undefined4 local_34;
  undefined4 uStack_30;
  int local_2c;
  undefined **local_28;
  uint local_24;
  undefined1 *puStack_20;
  void *local_1c;
  undefined1 *puStack_18;
  undefined4 local_14;
  
  puStack_20 = &stack0xfffffffc;
  local_14 = 0xffffffff;
  puStack_18 = &LAB_1004e998;
  local_1c = ExceptionList;
  local_24 = DAT_10069054 ^ (uint)&stack0xfffffff0;
  ExceptionList = &local_1c;
  local_28 = (undefined **)param_1;
  _memset(aiStack_104 + 1,0,0xb8);
  pwVar2 = (wchar_t *)this;
  if (7 < *(uint *)((int)this + 0x14)) {
                    /* WARNING: Load size is inaccurate */
    pwVar2 = *this;
  }
  FUN_10017d20(aiStack_104 + 1,pwVar2);
  *(undefined ***)((int)aiStack_104 + *(int *)(aiStack_104[1] + 4) + 4U) =
       std::basic_ifstream<char,struct_std::char_traits<char>_>::vftable;
  *(int *)((int)aiStack_104 + *(int *)(aiStack_104[1] + 4)) = *(int *)(aiStack_104[1] + 4) + -0x70;
  local_14 = 0;
  if (local_a4 == 0) {
    local_2c = 0;
    local_28 = &PTR_vftable_10069aa8;
    FUN_1000b9c0(&local_120,(LPCWSTR)this,&local_2c);
    local_118 = 0;
    local_108 = 0;
    aiStack_104[0] = 0xf;
    if (local_120 == 2) {
      FUN_10008e70(&local_118,(uint *)"failed open file",0x10);
      *param_1 = 0x6e;
      param_1[1] = (uint)&PTR_vftable_10069ab8;
      param_1[2] = 0;
      param_1[6] = 0;
      param_1[7] = 0;
      param_1[2] = local_118;
      param_1[3] = uStack_114;
      param_1[4] = uStack_110;
      param_1[5] = uStack_10c;
      *(ulonglong *)(param_1 + 6) = CONCAT44(aiStack_104[0],local_108);
      *(undefined1 *)(param_1 + 8) = 1;
      *(undefined ***)((int)aiStack_104 + *(int *)(aiStack_104[1] + 4) + 4U) =
           std::basic_ifstream<char,struct_std::char_traits<char>_>::vftable;
      *(int *)((int)aiStack_104 + *(int *)(aiStack_104[1] + 4)) =
           *(int *)(aiStack_104[1] + 4) + -0x70;
      FUN_10010880(local_f0);
      *(undefined ***)((int)aiStack_104 + *(int *)(aiStack_104[1] + 4) + 4U) =
           std::basic_istream<char,struct_std::char_traits<char>_>::vftable;
      *(int *)((int)aiStack_104 + *(int *)(aiStack_104[1] + 4)) =
           *(int *)(aiStack_104[1] + 4) + -0x18;
      local_14 = 1;
    }
    else {
      uVar4 = 0x1f;
      if (local_120 == 1) {
        uVar4 = 2;
      }
      FUN_10008e70(&local_118,(uint *)"failed open file",0x10);
      *param_1 = uVar4;
      param_1[1] = (uint)&PTR_vftable_10069ab8;
      param_1[2] = 0;
      param_1[6] = 0;
      param_1[7] = 0;
      param_1[2] = local_118;
      param_1[3] = uStack_114;
      param_1[4] = uStack_110;
      param_1[5] = uStack_10c;
      *(ulonglong *)(param_1 + 6) = CONCAT44(aiStack_104[0],local_108);
      *(undefined1 *)(param_1 + 8) = 1;
      *(undefined ***)((int)aiStack_104 + *(int *)(aiStack_104[1] + 4) + 4U) =
           std::basic_ifstream<char,struct_std::char_traits<char>_>::vftable;
      *(int *)((int)aiStack_104 + *(int *)(aiStack_104[1] + 4)) =
           *(int *)(aiStack_104[1] + 4) + -0x70;
      FUN_10010880(local_f0);
      *(undefined ***)((int)aiStack_104 + *(int *)(aiStack_104[1] + 4) + 4U) =
           std::basic_istream<char,struct_std::char_traits<char>_>::vftable;
      *(int *)((int)aiStack_104 + *(int *)(aiStack_104[1] + 4)) =
           *(int *)(aiStack_104[1] + 4) + -0x18;
      local_14 = 2;
    }
  }
  else {
    local_34 = 0;
    uStack_30 = 0xf;
    local_44 = 0;
    local_14 = 3;
    local_28 = (undefined **)CONCAT22(local_28._2_2_,1);
    piVar1 = *(int **)((int)auStack_c8 + *(int *)(aiStack_104[1] + 4));
    local_11c = CONCAT31((int3)(local_11c >> 8),piVar1 == (int *)0x0) & 0xffff00ff;
    FUN_10014920(&local_44,piVar1,local_11c,(int *)0x0,'\x01');
    if ((abStack_f4[*(int *)(aiStack_104[1] + 4)] & 6) != 0) {
      local_118 = 0;
      local_108 = 0;
      aiStack_104[0] = 0xf;
      FUN_10008e70(&local_118,(uint *)"failed read from file",0x15);
      local_140 = 0x1f;
      local_13c = &PTR_vftable_10069ab8;
      local_138 = local_118;
      uStack_134 = uStack_114;
      uStack_130 = uStack_110;
      uStack_12c = uStack_10c;
      local_128 = CONCAT44(aiStack_104[0],local_108);
      puVar3 = FUN_100143d0(local_160,&local_140);
      FUN_100146a0(param_1,puVar3);
      FUN_1000bd80((int)local_160);
      FUN_1000bd80((int)&local_140);
      FUN_10008fa0((int *)&local_44);
      FUN_1000fb00(aiStack_104 + 1);
      goto LAB_1000f5d0;
    }
    *param_1 = 0;
    param_1[4] = 0;
    param_1[5] = 0;
    *param_1 = local_44;
    param_1[1] = uStack_40;
    param_1[2] = uStack_3c;
    param_1[3] = uStack_38;
    local_44 = local_44 & 0xffffff00;
    *(ulonglong *)(param_1 + 4) = CONCAT44(uStack_30,local_34);
    *(undefined1 *)(param_1 + 8) = 0;
    local_34 = 0;
    uStack_30 = 0xf;
    *(undefined ***)((int)aiStack_104 + *(int *)(aiStack_104[1] + 4) + 4U) =
         std::basic_ifstream<char,struct_std::char_traits<char>_>::vftable;
    *(int *)((int)aiStack_104 + *(int *)(aiStack_104[1] + 4)) = *(int *)(aiStack_104[1] + 4) + -0x70
    ;
    FUN_10010880(local_f0);
    *(undefined ***)((int)aiStack_104 + *(int *)(aiStack_104[1] + 4) + 4U) =
         std::basic_istream<char,struct_std::char_traits<char>_>::vftable;
    *(int *)((int)aiStack_104 + *(int *)(aiStack_104[1] + 4)) = *(int *)(aiStack_104[1] + 4) + -0x18
    ;
    local_14 = 4;
  }
  local_90[0] = std::ios_base::vftable;
  std::ios_base::_Ios_base_dtor((ios_base *)local_90);
LAB_1000f5d0:
  ExceptionList = local_1c;
  FUN_1002e315(local_24 ^ (uint)&stack0xfffffff0);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_1000f600 @ 1000f600