void __thiscall FUN_100218c0(void *this,uint *param_1)

{
  uint uVar1;
  int iVar2;
  undefined8 uVar3;
  char *pcVar4;
  int *extraout_ECX;
  uint uStack_e0;
  undefined8 local_84;
  undefined4 local_7c;
  char local_70 [16];
  undefined4 local_60;
  int *local_5c;
  uint *local_54;
  uint local_50;
  uint local_4c;
  uint local_48;
  uint uStack_44;
  uint uStack_40;
  uint uStack_3c;
  undefined4 local_38;
  undefined4 uStack_34;
  char local_30;
  uint local_2c;
  undefined1 *puStack_24;
  undefined1 *local_20;
  void *local_1c;
  undefined1 *puStack_18;
  undefined4 local_14;
  
  puStack_24 = &stack0xfffffffc;
  local_14 = 0xffffffff;
  puStack_18 = &LAB_1004fddd;
  local_1c = ExceptionList;
  uStack_e0 = DAT_10069054 ^ (uint)&stack0xfffffff0;
  local_20 = (undefined1 *)&uStack_e0;
  ExceptionList = &local_1c;
  local_54 = param_1;
  local_2c = uStack_e0;
  FUN_10022b90(this,&local_50);
  local_14 = 0;
  if (local_30 == '\0') {
    local_14._0_1_ = 1;
    local_14._1_3_ = 0;
    FUN_10014700(&local_60,&local_50);
    local_14 = CONCAT31(local_14._1_3_,2);
    pcVar4 = FUN_1000f810(local_70,&local_60,1);
    *(char *)param_1 = *pcVar4;
    uVar1 = *(uint *)(pcVar4 + 0xc);
    param_1[2] = *(uint *)(pcVar4 + 8);
    param_1[3] = uVar1;
    *pcVar4 = '\0';
    pcVar4[8] = '\0';
    pcVar4[9] = '\0';
    pcVar4[10] = '\0';
    pcVar4[0xb] = '\0';
    pcVar4[0xc] = '\0';
    pcVar4[0xd] = '\0';
    pcVar4[0xe] = '\0';
    pcVar4[0xf] = '\0';
    *(undefined1 *)(param_1 + 8) = 0;
    FUN_1000e760(local_70);
    if (local_5c != (int *)0x0) {
      LOCK();
      iVar2 = local_5c[1] + -1;
      local_5c[1] = iVar2;
      UNLOCK();
      if (iVar2 == 0) {
        (**(code **)*local_5c)();
        LOCK();
        iVar2 = local_5c[2] + -1;
        local_5c[2] = iVar2;
        UNLOCK();
        if (iVar2 == 0) {
          (**(code **)(*local_5c + 4))();
        }
      }
    }
    FUN_1000f080((int *)&local_50);
    FUN_10021ac4();
    return;
  }
  if (local_30 != '\x01') {
    local_7c = 0;
    local_84 = 0;
    FUN_1000ee00((undefined4 *)&local_84);
                    /* WARNING: Subroutine does not return */
    __CxxThrowException_8(extraout_ECX,&DAT_10067650);
  }
  uVar3 = CONCAT44(uStack_34,local_38);
  param_1[1] = local_4c;
  *param_1 = local_50;
  param_1[2] = 0;
  param_1[6] = 0;
  param_1[7] = 0;
  param_1[2] = local_48;
  param_1[3] = uStack_44;
  param_1[4] = uStack_40;
  param_1[5] = uStack_3c;
  local_38 = 0;
  *(undefined8 *)(param_1 + 6) = uVar3;
  uStack_34 = 0xf;
  local_48 = local_48 & 0xffffff00;
  *(undefined1 *)(param_1 + 8) = 1;
  FUN_1000f080((int *)&local_50);
  FUN_10021ac4();
  return;
}


// FUNCTION_END

// FUNCTION_START: Catch@10021a1f @ 10021a1f