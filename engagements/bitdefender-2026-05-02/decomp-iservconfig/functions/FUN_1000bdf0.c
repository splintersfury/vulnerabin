void __fastcall FUN_1000bdf0(uint *param_1,uint *param_2)

{
  undefined8 uVar1;
  void *pvVar2;
  int *extraout_ECX;
  void *local_98 [5];
  uint local_84;
  void *local_80 [3];
  undefined8 local_74;
  uint local_6c;
  uint *local_64;
  uint local_60;
  uint uStack_5c;
  uint uStack_58;
  uint uStack_54;
  undefined8 local_50;
  uint local_48;
  uint uStack_44;
  uint uStack_40;
  uint uStack_3c;
  undefined8 local_38;
  undefined4 local_30;
  undefined4 uStack_2c;
  char local_28;
  uint local_24;
  undefined1 *puStack_20;
  void *local_1c;
  undefined1 *puStack_18;
  int local_14;
  
  puStack_20 = &stack0xfffffffc;
  local_14 = 0xffffffff;
  puStack_18 = &LAB_1004e520;
  local_1c = ExceptionList;
  local_24 = DAT_10069054 ^ (uint)&stack0xfffffff0;
  ExceptionList = &local_1c;
  local_64 = param_1;
  FUN_1000eb70(local_80,param_2);
  local_64 = (uint *)((uint)local_64 & 0xffffff00);
  local_14 = 0;
  FUN_100189b0(local_98);
  local_14._0_1_ = 1;
  FUN_1000b910(&local_60,(uint *)local_80,(uint *)local_98);
  local_14 = (uint)local_14._1_3_ << 8;
  if (7 < local_84) {
    pvVar2 = local_98[0];
    if (local_84 * 2 + 2 < 0x1000) {
LAB_1000beaa:
      FUN_1002e346(pvVar2);
      goto LAB_1000beb4;
    }
    pvVar2 = *(void **)((int)local_98[0] + -4);
    if ((uint)((int)local_98[0] + (-4 - (int)pvVar2)) < 0x20) goto LAB_1000beaa;
    FUN_10032f7f();
LAB_1000bfa1:
    FUN_10032f7f();
LAB_1000bfa6:
    local_6c = 0;
    local_74 = 0;
    FUN_1000ee00((undefined4 *)&local_74);
                    /* WARNING: Subroutine does not return */
    __CxxThrowException_8(extraout_ECX,&DAT_10067650);
  }
LAB_1000beb4:
  local_28 = '\0';
  local_48 = local_60;
  uStack_44 = uStack_5c;
  uStack_40 = uStack_58;
  uStack_3c = uStack_54;
  local_14 = -1;
  local_38 = local_50;
  if (7 < local_6c) {
    pvVar2 = local_80[0];
    if (0xfff < local_6c * 2 + 2) {
      pvVar2 = *(void **)((int)local_80[0] + -4);
      if (0x1f < (uint)((int)local_80[0] + (-4 - (int)pvVar2))) goto LAB_1000bfa1;
    }
    FUN_1002e346(pvVar2);
  }
  local_14 = 2;
  if (local_28 == '\0') {
    FUN_1000bba0(&local_48,param_1);
  }
  else {
    if (local_28 != '\x01') goto LAB_1000bfa6;
    uVar1 = CONCAT44(uStack_2c,local_30);
    *param_1 = local_48;
    param_1[1] = uStack_44;
    param_1[2] = 0;
    param_1[6] = 0;
    param_1[7] = 0;
    param_1[2] = uStack_40;
    param_1[3] = uStack_3c;
    param_1[4] = (uint)local_38;
    param_1[5] = local_38._4_4_;
    local_30 = 0;
    *(undefined8 *)(param_1 + 6) = uVar1;
    uStack_2c = 0xf;
    uStack_40 = uStack_40 & 0xffffff00;
    *(undefined1 *)(param_1 + 0xc) = 1;
  }
  FUN_1000e210((int *)&local_48);
  ExceptionList = local_1c;
  FUN_1002e315(local_24 ^ (uint)&stack0xfffffff0);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_1000bfd0 @ 1000bfd0