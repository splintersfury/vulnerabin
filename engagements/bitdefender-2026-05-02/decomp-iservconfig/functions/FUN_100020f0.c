void __thiscall FUN_100020f0(void *this,undefined4 param_1,int *param_2,uint *param_3)

{
  undefined2 *puVar1;
  code *pcVar2;
  int iVar3;
  uint uVar4;
  undefined4 ****ppppuVar5;
  void *pvVar6;
  void *local_78 [5];
  uint local_64;
  undefined4 ***local_60;
  undefined4 uStack_5c;
  undefined4 uStack_58;
  undefined4 uStack_54;
  undefined8 local_50;
  undefined4 ***local_48;
  undefined4 uStack_44;
  undefined4 uStack_40;
  undefined4 uStack_3c;
  int local_38;
  uint uStack_34;
  void *local_30;
  undefined4 ***local_2c;
  uint local_28;
  uint local_24;
  undefined1 *puStack_20;
  void *local_1c;
  undefined1 *puStack_18;
  undefined4 local_14;
  
  puStack_20 = &stack0xfffffffc;
  local_14 = 0xffffffff;
  puStack_18 = &LAB_1004d975;
  local_1c = ExceptionList;
  uVar4 = DAT_10069054 ^ (uint)&stack0xfffffff0;
  ExceptionList = &local_1c;
  local_30 = this;
  local_24 = uVar4;
  FUN_100056d0(&local_48,param_3);
  iVar3 = local_38;
  local_30 = (void *)param_1;
  local_14 = 0;
  if (local_38 != 0) {
    if (uStack_34 - local_38 < 2) {
      local_28 = local_28 & 0xffffff00;
      FUN_100062b0(&local_48,2,local_28,(uint *)&DAT_1005e234,2);
    }
    else {
      ppppuVar5 = &local_48;
      if (0xf < uStack_34) {
        ppppuVar5 = (undefined4 ****)local_48;
      }
      puVar1 = (undefined2 *)((int)ppppuVar5 + local_38);
      local_38 = local_38 + 2;
      *puVar1 = 0x203a;
      *(undefined1 *)((int)ppppuVar5 + iVar3 + 2) = 0;
    }
  }
  (**(code **)(*param_2 + 8))(local_78,local_30,uVar4);
  local_14 = CONCAT31(local_14._1_3_,1);
  FUN_10005610(&local_48,(uint *)local_78);
  if (0xf < local_64) {
    pvVar6 = local_78[0];
    if (0xfff < local_64 + 1) {
      pvVar6 = *(void **)((int)local_78[0] + -4);
      if (0x1f < (uint)((int)local_78[0] + (-4 - (int)pvVar6))) {
        FUN_10032f7f();
        goto LAB_100022b5;
      }
    }
    FUN_1002e346(pvVar6);
  }
  *(undefined ***)this = std::exception::vftable;
  local_50 = CONCAT44(uStack_34,local_38);
  *(undefined8 *)((int)this + 4) = 0;
  local_60 = local_48;
  uStack_5c = uStack_44;
  uStack_58 = uStack_40;
  uStack_54 = uStack_3c;
  local_2c = &local_60;
  if (0xf < uStack_34) {
    local_2c = local_48;
  }
  local_38 = 0;
  uStack_34 = 0xf;
  local_48 = (undefined4 ***)((uint)local_48 & 0xffffff00);
  local_28 = CONCAT31(local_28._1_3_,1);
  ___std_exception_copy(&local_2c,(undefined4 *)((int)this + 4));
  *(undefined ***)this = std::runtime_error::vftable;
  if (0xf < local_50._4_4_) {
    ppppuVar5 = (undefined4 ****)local_60;
    if (0xfff < local_50._4_4_ + 1) {
      ppppuVar5 = (undefined4 ****)local_60[-1];
      if (0x1f < (uint)((int)local_60 + (-4 - (int)ppppuVar5))) {
LAB_100022b5:
        FUN_10032f7f();
        pcVar2 = (code *)swi(3);
        (*pcVar2)();
        return;
      }
    }
    FUN_1002e346(ppppuVar5);
  }
  *(undefined ***)this = std::_System_error::vftable;
  *(undefined4 *)((int)this + 0xc) = param_1;
  *(int **)((int)this + 0x10) = param_2;
  ExceptionList = local_1c;
  FUN_1002e315(local_24 ^ (uint)&stack0xfffffff0);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_100022c0 @ 100022c0