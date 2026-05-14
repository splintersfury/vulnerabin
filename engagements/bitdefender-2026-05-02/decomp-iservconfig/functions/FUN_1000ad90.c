void __fastcall FUN_1000ad90(undefined4 *param_1,uint param_2,uint *param_3)

{
  code *pcVar1;
  void *pvVar2;
  uint *puVar3;
  undefined4 ****ppppuVar4;
  void *local_7c [4];
  undefined4 local_6c;
  uint local_68;
  void *local_64 [4];
  undefined4 local_54;
  uint local_50;
  undefined4 *local_4c;
  uint local_48;
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
  puStack_18 = &LAB_1004e425;
  local_1c = ExceptionList;
  local_24 = DAT_10069054 ^ (uint)&stack0xfffffff0;
  ExceptionList = &local_1c;
  local_54 = 0;
  local_50 = 0xf;
  local_64[0] = (void *)0x0;
  local_4c = param_1;
  local_48 = param_2;
  FUN_10008e70(local_64,(uint *)"type_error",10);
  local_14 = 0;
  pvVar2 = (void *)FUN_1000a2e0((uint *)local_7c,(uint *)local_64,local_48);
  local_14 = CONCAT31(local_14._1_3_,1);
  puVar3 = FUN_10005610(pvVar2,param_3);
  local_3c = (undefined4 ***)*puVar3;
  uStack_38 = puVar3[1];
  uStack_34 = puVar3[2];
  uStack_30 = puVar3[3];
  local_2c = *(undefined8 *)(puVar3 + 4);
  puVar3[4] = 0;
  puVar3[5] = 0xf;
  *(undefined1 *)puVar3 = 0;
  if (0xf < local_68) {
    pvVar2 = local_7c[0];
    if (local_68 + 1 < 0x1000) {
LAB_1000ae74:
      FUN_1002e346(pvVar2);
      goto LAB_1000ae7e;
    }
    pvVar2 = *(void **)((int)local_7c[0] + -4);
    if ((uint)((int)local_7c[0] + (-4 - (int)pvVar2)) < 0x20) goto LAB_1000ae74;
LAB_1000af62:
    FUN_10032f7f();
LAB_1000af67:
    FUN_10032f7f();
    pcVar1 = (code *)swi(3);
    (*pcVar1)();
    return;
  }
LAB_1000ae7e:
  local_6c = 0;
  local_68 = 0xf;
  local_7c[0] = (void *)((uint)local_7c[0] & 0xffffff00);
  if (0xf < local_50) {
    pvVar2 = local_64[0];
    if (0xfff < local_50 + 1) {
      pvVar2 = *(void **)((int)local_64[0] + -4);
      if (0x1f < (uint)((int)local_64[0] + (-4 - (int)pvVar2))) goto LAB_1000af62;
    }
    FUN_1002e346(pvVar2);
  }
  *(undefined8 *)(param_1 + 1) = 0;
  local_44 = &local_3c;
  if (0xf < local_2c._4_4_) {
    local_44 = local_3c;
  }
  param_1[3] = local_48;
  *param_1 = nlohmann::detail::exception::vftable;
  param_1[4] = std::exception::vftable;
  *(undefined8 *)(param_1 + 5) = 0;
  local_40 = 1;
  ___std_exception_copy(&local_44,param_1 + 5);
  param_1[4] = std::runtime_error::vftable;
  *param_1 = nlohmann::detail::type_error::vftable;
  if (0xf < local_2c._4_4_) {
    ppppuVar4 = (undefined4 ****)local_3c;
    if (0xfff < local_2c._4_4_ + 1) {
      ppppuVar4 = (undefined4 ****)local_3c[-1];
      if (0x1f < (uint)((int)local_3c + (-4 - (int)ppppuVar4))) goto LAB_1000af67;
    }
    FUN_1002e346(ppppuVar4);
  }
  ExceptionList = local_1c;
  FUN_1002e315(local_24 ^ (uint)&stack0xfffffff0);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_1000af70 @ 1000af70