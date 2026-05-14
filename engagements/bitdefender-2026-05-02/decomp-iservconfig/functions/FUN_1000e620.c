int __thiscall FUN_1000e620(void *this,uint *param_1)

{
  byte *pbVar1;
  uint uVar2;
  uint *puVar3;
  uint uStack_c0;
  uint local_b0 [6];
  undefined1 local_98 [24];
  uint auStack_80 [6];
  int local_68 [7];
  int aiStack_4c [7];
  uint auStack_30 [3];
  int local_24 [2];
  int local_1c;
  undefined1 *local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_1004e95b;
  local_10 = ExceptionList;
  uStack_c0 = DAT_10069054 ^ (uint)&stack0xfffffffc;
  local_14 = (undefined1 *)&uStack_c0;
  ExceptionList = &local_10;
                    /* WARNING: Load size is inaccurate */
  if (*this != '\x01') {
    puVar3 = (uint *)FUN_1000f7b0((undefined1 *)this);
    puVar3 = FUN_10005690(local_98,puVar3);
    local_8 = 4;
    puVar3 = FUN_10005f20(local_b0,(uint *)"cannot use at() with ",puVar3);
    local_8 = CONCAT31(local_8._1_3_,5);
    FUN_1000ad90(local_68,0x130,puVar3);
                    /* WARNING: Subroutine does not return */
    __CxxThrowException_8(local_68,&DAT_10067608);
  }
  local_8 = 0;
  local_14 = (undefined1 *)&uStack_c0;
  FUN_10014a40(*(void **)((int)this + 8),local_24,(byte *)param_1);
  if (*(char *)(local_1c + 0xd) == '\0') {
    pbVar1 = (byte *)(local_1c + 0x10);
    if (0xf < *(uint *)(local_1c + 0x24)) {
      pbVar1 = *(byte **)pbVar1;
    }
    puVar3 = param_1;
    if (0xf < param_1[5]) {
      puVar3 = (uint *)*param_1;
    }
    uVar2 = FUN_100148a0((byte *)puVar3,param_1[4],pbVar1,*(uint *)(local_1c + 0x20));
    if (-1 < (int)uVar2) {
      ExceptionList = local_10;
      return local_1c + 0x28;
    }
  }
  FUN_1002c874("invalid map<K, T> key");
  puVar3 = FUN_10014120(auStack_30,(uint *)"key \'",param_1);
  local_8._0_1_ = 2;
  puVar3 = FUN_10014250(auStack_80,puVar3,(uint *)"\' not found");
  local_8 = CONCAT31(local_8._1_3_,3);
  FUN_1000af70(aiStack_4c,0x193,puVar3);
                    /* WARNING: Subroutine does not return */
  __CxxThrowException_8(aiStack_4c,&DAT_10067618);
}


// FUNCTION_END

// FUNCTION_START: Catch@1000e713 @ 1000e713