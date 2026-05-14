void __thiscall FUN_1000bba0(void *this,uint *param_1)

{
  undefined8 uVar1;
  undefined4 *puVar2;
  int *extraout_ECX;
  uint uStack_d8;
  int local_a8 [16];
  undefined8 local_68;
  undefined4 local_60;
  uint *local_5c;
  uint local_58;
  uint local_54;
  uint local_50;
  uint uStack_4c;
  uint uStack_48;
  uint uStack_44;
  undefined4 local_40;
  undefined4 uStack_3c;
  char local_38;
  uint local_2c;
  undefined1 *puStack_24;
  undefined1 *local_20;
  void *local_1c;
  undefined1 *puStack_18;
  undefined4 local_14;
  
  puStack_24 = &stack0xfffffffc;
  local_14 = 0xffffffff;
  puStack_18 = &LAB_1004e4cd;
  local_1c = ExceptionList;
  uStack_d8 = DAT_10069054 ^ (uint)&stack0xfffffff0;
  local_20 = (undefined1 *)&uStack_d8;
  ExceptionList = &local_1c;
  local_5c = param_1;
  local_2c = uStack_d8;
  FUN_1000e330(this,&local_58);
  local_14 = 0;
  if (local_38 == '\0') {
    local_14 = 1;
    puVar2 = FUN_10014480(&local_58,local_a8);
    FUN_10017630(param_1,puVar2);
    *(undefined1 *)(param_1 + 0xc) = 0;
    FUN_1000bb10(local_a8);
    FUN_1000e5a0((char *)&local_58);
    FUN_1000bd02();
    return;
  }
  if (local_38 != '\x01') {
    local_60 = 0;
    local_68 = 0;
    FUN_1000ee00((undefined4 *)&local_68);
                    /* WARNING: Subroutine does not return */
    __CxxThrowException_8(extraout_ECX,&DAT_10067650);
  }
  uVar1 = CONCAT44(uStack_3c,local_40);
  param_1[1] = local_54;
  *param_1 = local_58;
  param_1[2] = 0;
  param_1[6] = 0;
  param_1[7] = 0;
  param_1[2] = local_50;
  param_1[3] = uStack_4c;
  param_1[4] = uStack_48;
  param_1[5] = uStack_44;
  local_40 = 0;
  *(undefined8 *)(param_1 + 6) = uVar1;
  uStack_3c = 0xf;
  local_50 = local_50 & 0xffffff00;
  *(undefined1 *)(param_1 + 0xc) = 1;
  FUN_1000e5a0((char *)&local_58);
  FUN_1000bd02();
  return;
}


// FUNCTION_END

// FUNCTION_START: Catch@1000bca1 @ 1000bca1