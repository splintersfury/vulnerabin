void __cdecl FUN_1000a5b0(undefined4 *param_1,uint *param_2)

{
  undefined4 uVar1;
  code *pcVar2;
  uint *puVar3;
  void *pvVar4;
  uint *puVar5;
  undefined4 ****ppppuVar6;
  void *local_e0 [5];
  uint local_cc;
  void *local_c8;
  uint uStack_c4;
  uint uStack_c0;
  uint uStack_bc;
  undefined8 local_b8;
  void *local_b0 [4];
  undefined4 local_a0;
  uint local_9c;
  void *local_98 [4];
  undefined4 local_88;
  uint local_84;
  void *local_80 [4];
  undefined4 local_70;
  uint local_6c;
  void *local_68;
  uint uStack_64;
  uint uStack_60;
  uint uStack_5c;
  undefined8 local_58;
  undefined4 *local_50;
  undefined4 *local_4c;
  undefined4 local_48;
  undefined4 ***local_44;
  undefined1 local_40;
  undefined4 ***local_3c;
  uint uStack_38;
  uint uStack_34;
  uint uStack_30;
  undefined8 local_2c;
  uint local_24;
  undefined1 *puStack_20;
  void *local_1c;
  undefined1 *puStack_18;
  undefined4 local_14;
  
  puStack_20 = &stack0xfffffffc;
  local_14 = 0xffffffff;
  puStack_18 = &LAB_1004e391;
  local_1c = ExceptionList;
  local_24 = DAT_10069054 ^ (uint)&stack0xfffffff0;
  ExceptionList = &local_1c;
  local_4c = param_1;
  puVar3 = (uint *)FUN_1000a970(local_e0,(int)param_1);
  local_14 = 0;
  local_70 = 0;
  local_6c = 0xf;
  local_80[0] = (void *)0x0;
  FUN_10008e70(local_80,(uint *)"parse_error",0xb);
  local_14._0_1_ = 1;
  pvVar4 = (void *)FUN_1000a2e0((uint *)local_b0,(uint *)local_80,0x65);
  local_14._0_1_ = 2;
  puVar5 = FUN_100055a0(pvVar4,(uint *)"parse error");
  local_c8 = (void *)*puVar5;
  uStack_c4 = puVar5[1];
  uStack_c0 = puVar5[2];
  uStack_bc = puVar5[3];
  local_b8 = *(undefined8 *)(puVar5 + 4);
  puVar5[4] = 0;
  puVar5[5] = 0xf;
  *(undefined1 *)puVar5 = 0;
  local_14._0_1_ = 3;
  FUN_10018020(local_98,local_48,(uint *)&local_c8,puVar3);
  local_14._0_1_ = 4;
  puVar3 = FUN_100055a0(local_98,(uint *)&DAT_1005e234);
  local_68 = (void *)*puVar3;
  uStack_64 = puVar3[1];
  uStack_60 = puVar3[2];
  uStack_5c = puVar3[3];
  local_58 = *(undefined8 *)(puVar3 + 4);
  puVar3[4] = 0;
  puVar3[5] = 0xf;
  *(undefined1 *)puVar3 = 0;
  local_14 = CONCAT31(local_14._1_3_,5);
  puVar3 = FUN_10005610(&local_68,param_2);
  local_3c = (undefined4 ***)*puVar3;
  uStack_38 = puVar3[1];
  uStack_34 = puVar3[2];
  uStack_30 = puVar3[3];
  local_2c = *(undefined8 *)(puVar3 + 4);
  puVar3[4] = 0;
  puVar3[5] = 0xf;
  *(undefined1 *)puVar3 = 0;
  if (0xf < local_58._4_4_) {
    pvVar4 = local_68;
    if (local_58._4_4_ + 1 < 0x1000) {
LAB_1000a74e:
      FUN_1002e346(pvVar4);
      goto LAB_1000a758;
    }
    pvVar4 = *(void **)((int)local_68 - 4);
    if ((uint)((int)local_68 + (-4 - (int)pvVar4)) < 0x20) goto LAB_1000a74e;
LAB_1000a95d:
    FUN_10032f7f();
LAB_1000a962:
    FUN_10032f7f();
    pcVar2 = (code *)swi(3);
    (*pcVar2)();
    return;
  }
LAB_1000a758:
  local_58 = 0xf00000000;
  local_68 = (void *)((uint)local_68 & 0xffffff00);
  if (0xf < local_84) {
    pvVar4 = local_98[0];
    if (0xfff < local_84 + 1) {
      pvVar4 = *(void **)((int)local_98[0] + -4);
      if (0x1f < (uint)((int)local_98[0] + (-4 - (int)pvVar4))) goto LAB_1000a95d;
    }
    FUN_1002e346(pvVar4);
  }
  local_88 = 0;
  local_84 = 0xf;
  local_98[0] = (void *)((uint)local_98[0] & 0xffffff00);
  if (0xf < local_b8._4_4_) {
    pvVar4 = local_c8;
    if (0xfff < local_b8._4_4_ + 1) {
      pvVar4 = *(void **)((int)local_c8 - 4);
      if (0x1f < (uint)((int)local_c8 + (-4 - (int)pvVar4))) goto LAB_1000a95d;
    }
    FUN_1002e346(pvVar4);
  }
  if (0xf < local_9c) {
    pvVar4 = local_b0[0];
    if (0xfff < local_9c + 1) {
      pvVar4 = *(void **)((int)local_b0[0] + -4);
      if (0x1f < (uint)((int)local_b0[0] + (-4 - (int)pvVar4))) goto LAB_1000a95d;
    }
    FUN_1002e346(pvVar4);
  }
  local_a0 = 0;
  local_9c = 0xf;
  local_b0[0] = (void *)((uint)local_b0[0] & 0xffffff00);
  if (0xf < local_6c) {
    pvVar4 = local_80[0];
    if (0xfff < local_6c + 1) {
      pvVar4 = *(void **)((int)local_80[0] + -4);
      if (0x1f < (uint)((int)local_80[0] + (-4 - (int)pvVar4))) goto LAB_1000a95d;
    }
    FUN_1002e346(pvVar4);
  }
  if (0xf < local_cc) {
    pvVar4 = local_e0[0];
    if (0xfff < local_cc + 1) {
      pvVar4 = *(void **)((int)local_e0[0] + -4);
      if (0x1f < (uint)((int)local_e0[0] + (-4 - (int)pvVar4))) goto LAB_1000a95d;
    }
    FUN_1002e346(pvVar4);
  }
  local_44 = &local_3c;
  if (0xf < local_2c._4_4_) {
    local_44 = local_3c;
  }
  uVar1 = *local_4c;
  *(undefined8 *)(local_50 + 1) = 0;
  *local_50 = nlohmann::detail::exception::vftable;
  local_50[3] = 0x65;
  local_50[4] = std::exception::vftable;
  *(undefined8 *)(local_50 + 5) = 0;
  local_40 = 1;
  ___std_exception_copy(&local_44,local_50 + 5);
  local_50[4] = std::runtime_error::vftable;
  *local_50 = nlohmann::detail::parse_error::vftable;
  local_50[7] = uVar1;
  if (0xf < local_2c._4_4_) {
    ppppuVar6 = (undefined4 ****)local_3c;
    if (0xfff < local_2c._4_4_ + 1) {
      ppppuVar6 = (undefined4 ****)local_3c[-1];
      if (0x1f < (uint)((int)local_3c + (-4 - (int)ppppuVar6))) goto LAB_1000a962;
    }
    FUN_1002e346(ppppuVar6);
  }
  ExceptionList = local_1c;
  FUN_1002e315(local_24 ^ (uint)&stack0xfffffff0);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_1000a970 @ 1000a970