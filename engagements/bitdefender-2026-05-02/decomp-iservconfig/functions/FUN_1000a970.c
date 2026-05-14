void * __fastcall FUN_1000a970(void *param_1,int param_2)

{
  code *pcVar1;
  uint *puVar2;
  uint *puVar3;
  void *pvVar4;
  void *pvVar5;
  void *local_88 [5];
  uint local_74;
  void *local_70;
  uint uStack_6c;
  uint uStack_68;
  uint uStack_64;
  undefined8 local_60;
  void *local_58 [4];
  undefined4 local_48;
  uint local_44;
  void *local_40 [4];
  undefined4 local_30;
  uint local_2c;
  void *local_28;
  void *local_24;
  undefined1 *puStack_20;
  void *local_1c;
  undefined1 *puStack_18;
  undefined4 local_14;
  
  puStack_20 = &stack0xfffffffc;
  local_14 = 0xffffffff;
  puStack_18 = &LAB_1004e3e5;
  local_1c = ExceptionList;
  ExceptionList = &local_1c;
  local_28 = param_1;
  local_24 = param_1;
  puVar2 = (uint *)FUN_1001bf60((char *)local_88,*(uint *)(param_2 + 4));
  local_14 = 0;
  puVar3 = (uint *)FUN_1001bf60((char *)local_58,*(int *)(param_2 + 8) + 1);
  local_14._0_1_ = 1;
  puVar3 = FUN_10005f20((uint *)local_40,(uint *)" at line ",puVar3);
  local_14._0_1_ = 2;
  puVar3 = FUN_100055a0(puVar3,(uint *)", column ");
  pvVar4 = local_28;
  local_70 = (void *)*puVar3;
  uStack_6c = puVar3[1];
  uStack_68 = puVar3[2];
  uStack_64 = puVar3[3];
  local_60 = *(undefined8 *)(puVar3 + 4);
  puVar3[4] = 0;
  puVar3[5] = 0xf;
  *(undefined1 *)puVar3 = 0;
  local_14 = CONCAT31(local_14._1_3_,3);
  FUN_10018020(local_28,local_24,(uint *)&local_70,puVar2);
  if (0xf < local_60._4_4_) {
    pvVar5 = local_70;
    if (0xfff < local_60._4_4_ + 1) {
      pvVar5 = *(void **)((int)local_70 - 4);
      if (0x1f < (uint)((int)local_70 + (-4 - (int)pvVar5))) goto LAB_1000ab37;
    }
    FUN_1002e346(pvVar5);
  }
  if (0xf < local_2c) {
    pvVar5 = local_40[0];
    if (0xfff < local_2c + 1) {
      pvVar5 = *(void **)((int)local_40[0] + -4);
      if (0x1f < (uint)((int)local_40[0] + (-4 - (int)pvVar5))) goto LAB_1000ab37;
    }
    FUN_1002e346(pvVar5);
  }
  local_30 = 0;
  local_2c = 0xf;
  local_40[0] = (void *)((uint)local_40[0] & 0xffffff00);
  if (0xf < local_44) {
    pvVar5 = local_58[0];
    if (0xfff < local_44 + 1) {
      pvVar5 = *(void **)((int)local_58[0] + -4);
      if (0x1f < (uint)((int)local_58[0] + (-4 - (int)pvVar5))) goto LAB_1000ab37;
    }
    FUN_1002e346(pvVar5);
  }
  local_48 = 0;
  local_44 = 0xf;
  local_58[0] = (void *)((uint)local_58[0] & 0xffffff00);
  if (0xf < local_74) {
    pvVar5 = local_88[0];
    if (0xfff < local_74 + 1) {
      pvVar5 = *(void **)((int)local_88[0] + -4);
      if (0x1f < (uint)((int)local_88[0] + (-4 - (int)pvVar5))) {
LAB_1000ab37:
        FUN_10032f7f();
        pcVar1 = (code *)swi(3);
        pvVar4 = (void *)(*pcVar1)();
        return pvVar4;
      }
    }
    FUN_1002e346(pvVar5);
  }
  ExceptionList = local_1c;
  return pvVar4;
}


// FUNCTION_END

// FUNCTION_START: FUN_1000ab40 @ 1000ab40