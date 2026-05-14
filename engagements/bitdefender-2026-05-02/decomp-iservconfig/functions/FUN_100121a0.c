void __thiscall FUN_100121a0(void *this,undefined4 *param_1)

{
  byte bVar1;
  byte *pbVar2;
  uint uVar3;
  undefined4 *puVar4;
  void *extraout_ECX;
  void *extraout_ECX_00;
  byte *pbVar5;
  uint local_30;
  undefined8 local_24;
  undefined1 local_1c;
  uint local_18;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_10 = ExceptionList;
  puStack_c = &LAB_1004ed4e;
  local_18 = DAT_10069054 ^ (uint)&stack0xfffffffc;
  ExceptionList = &local_10;
  *param_1 = 0;
  param_1[4] = 0;
  param_1[5] = 0xf;
  *(undefined1 *)param_1 = 0;
  local_8 = 0;
  pbVar2 = *(byte **)((int)this + 0x20);
  for (pbVar5 = *(byte **)((int)this + 0x1c); pbVar5 != pbVar2; pbVar5 = pbVar5 + 1) {
    bVar1 = *pbVar5;
    this = (void *)CONCAT31((int3)((uint)this >> 8),bVar1);
    if (bVar1 < 0x20) {
      local_24 = 0;
      local_1c = 0;
      FUN_1001bf40(&local_24,9,"<U+%.4X>");
      FUN_100055a0(param_1,(uint *)&local_24);
      this = extraout_ECX;
    }
    else {
      uVar3 = param_1[4];
      if (uVar3 < (uint)param_1[5]) {
        param_1[4] = uVar3 + 1;
        puVar4 = param_1;
        if (0xf < (uint)param_1[5]) {
          puVar4 = (undefined4 *)*param_1;
        }
        *(byte *)((int)puVar4 + uVar3) = bVar1;
        *(undefined1 *)((int)puVar4 + uVar3 + 1) = 0;
      }
      else {
        local_30 = local_30 & 0xffffff00;
        FUN_10014ac0(param_1,this,local_30,bVar1);
        this = extraout_ECX_00;
      }
    }
  }
  ExceptionList = local_10;
  FUN_1002e315(local_18 ^ (uint)&stack0xfffffffc);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_100122b0 @ 100122b0