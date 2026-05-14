void __thiscall FUN_1000b150(void *this,uint *param_1)

{
  code *pcVar1;
  void *pvVar2;
  uint *puVar3;
  undefined4 ****ppppuVar4;
  void *local_78 [4];
  undefined4 local_68;
  uint local_64;
  void *local_60 [4];
  undefined4 local_50;
  uint local_4c;
  void *local_48;
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
  puStack_18 = &LAB_1004e465;
  local_1c = ExceptionList;
  local_24 = DAT_10069054 ^ (uint)&stack0xfffffff0;
  ExceptionList = &local_1c;
  local_50 = 0;
  local_4c = 0xf;
  local_60[0] = (void *)0x0;
  local_48 = this;
  FUN_10008e70(local_60,(uint *)"other_error",0xb);
  local_14 = 0;
  pvVar2 = (void *)FUN_1000a2e0((uint *)local_78,(uint *)local_60,500);
  local_14 = CONCAT31(local_14._1_3_,1);
  puVar3 = FUN_10005610(pvVar2,param_1);
  local_3c = (undefined4 ***)*puVar3;
  uStack_38 = puVar3[1];
  uStack_34 = puVar3[2];
  uStack_30 = puVar3[3];
  local_2c = *(undefined8 *)(puVar3 + 4);
  puVar3[4] = 0;
  puVar3[5] = 0xf;
  *(undefined1 *)puVar3 = 0;
  if (0xf < local_64) {
    pvVar2 = local_78[0];
    if (local_64 + 1 < 0x1000) {
LAB_1000b233:
      FUN_1002e346(pvVar2);
      goto LAB_1000b23d;
    }
    pvVar2 = *(void **)((int)local_78[0] + -4);
    if ((uint)((int)local_78[0] + (-4 - (int)pvVar2)) < 0x20) goto LAB_1000b233;
LAB_1000b322:
    FUN_10032f7f();
LAB_1000b327:
    FUN_10032f7f();
    pcVar1 = (code *)swi(3);
    (*pcVar1)();
    return;
  }
LAB_1000b23d:
  local_68 = 0;
  local_64 = 0xf;
  local_78[0] = (void *)((uint)local_78[0] & 0xffffff00);
  if (0xf < local_4c) {
    pvVar2 = local_60[0];
    if (0xfff < local_4c + 1) {
      pvVar2 = *(void **)((int)local_60[0] + -4);
      if (0x1f < (uint)((int)local_60[0] + (-4 - (int)pvVar2))) goto LAB_1000b322;
    }
    FUN_1002e346(pvVar2);
  }
  local_40 = 1;
  *(undefined8 *)((int)this + 4) = 0;
  local_44 = &local_3c;
  if (0xf < local_2c._4_4_) {
    local_44 = local_3c;
  }
  *(undefined ***)this = nlohmann::detail::exception::vftable;
  *(undefined4 *)((int)this + 0xc) = 500;
  *(undefined ***)((int)this + 0x10) = std::exception::vftable;
  *(undefined8 *)((int)this + 0x14) = 0;
  ___std_exception_copy(&local_44,(undefined4 *)((int)this + 0x14));
  *(undefined ***)((int)this + 0x10) = std::runtime_error::vftable;
  *(undefined ***)this = nlohmann::detail::other_error::vftable;
  if (0xf < local_2c._4_4_) {
    ppppuVar4 = (undefined4 ****)local_3c;
    if (0xfff < local_2c._4_4_ + 1) {
      ppppuVar4 = (undefined4 ****)local_3c[-1];
      if (0x1f < (uint)((int)local_3c + (-4 - (int)ppppuVar4))) goto LAB_1000b327;
    }
    FUN_1002e346(ppppuVar4);
  }
  ExceptionList = local_1c;
  FUN_1002e315(local_24 ^ (uint)&stack0xfffffff0);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_1000b330 @ 1000b330