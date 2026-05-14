void __thiscall FUN_10014920(void *this,int *param_1,undefined4 param_2,int *param_3,char param_4)

{
  undefined8 uVar1;
  code *pcVar2;
  undefined4 uVar3;
  undefined4 uVar4;
  undefined4 uVar5;
  uint ****ppppuVar6;
  uint ***local_3c;
  undefined4 uStack_38;
  undefined4 uStack_34;
  undefined4 uStack_30;
  undefined8 local_2c;
  uint local_24;
  undefined1 *puStack_20;
  void *local_1c;
  undefined1 *puStack_18;
  undefined4 local_14;
  
  puStack_20 = &stack0xfffffffc;
  local_14 = 0xffffffff;
  puStack_18 = &LAB_1004eebd;
  local_1c = ExceptionList;
  local_24 = DAT_10069054 ^ (uint)&stack0xfffffff0;
  ExceptionList = &local_1c;
  local_2c = 0xf00000000;
  local_3c = (uint ***)0x0;
  FUN_1001ada0(&local_3c,param_1,param_2,param_3,param_4);
  local_14 = 0;
  if (*(uint *)((int)this + 0x14) < local_2c._4_4_) {
                    /* WARNING: Load size is inaccurate */
    ppppuVar6 = *this;
    uVar3 = *(undefined4 *)((int)this + 4);
    uVar4 = *(undefined4 *)((int)this + 8);
    uVar5 = *(undefined4 *)((int)this + 0xc);
    uVar1 = *(undefined8 *)((int)this + 0x10);
    *(uint ****)this = local_3c;
    *(undefined4 *)((int)this + 4) = uStack_38;
    *(undefined4 *)((int)this + 8) = uStack_34;
    *(undefined4 *)((int)this + 0xc) = uStack_30;
    *(undefined8 *)((int)this + 0x10) = local_2c;
    local_3c = (uint ***)ppppuVar6;
    uStack_38 = uVar3;
    uStack_34 = uVar4;
    uStack_30 = uVar5;
    local_2c = uVar1;
  }
  else {
    ppppuVar6 = &local_3c;
    if (0xf < local_2c._4_4_) {
      ppppuVar6 = (uint ****)local_3c;
    }
    FUN_10008e70(this,(uint *)ppppuVar6,(uint)local_2c);
  }
  if (0xf < local_2c._4_4_) {
    ppppuVar6 = (uint ****)local_3c;
    if (0xfff < local_2c._4_4_ + 1) {
      ppppuVar6 = (uint ****)local_3c[-1];
      if (0x1f < (uint)((int)local_3c + (-4 - (int)ppppuVar6))) {
        FUN_10032f7f();
        pcVar2 = (code *)swi(3);
        (*pcVar2)();
        return;
      }
    }
    FUN_1002e346(ppppuVar6);
  }
  ExceptionList = local_1c;
  FUN_1002e315(local_24 ^ (uint)&stack0xfffffff0);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_10014a40 @ 10014a40