void FUN_10009ea0(undefined4 *param_1,DWORD param_2)

{
  uint *puVar1;
  uint uVar2;
  uint *local_1c;
  undefined4 *local_18;
  uint local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_1004e28d;
  local_10 = ExceptionList;
  local_14 = DAT_10069054 ^ (uint)&stack0xfffffffc;
  ExceptionList = &local_10;
  local_18 = param_1;
  local_1c = (uint *)0x0;
  local_18 = (undefined4 *)___std_system_error_allocate_message_8(param_2,(int *)&local_1c);
  local_8 = 0;
  *param_1 = 0;
  param_1[4] = 0;
  param_1[5] = 0xf;
  *(undefined1 *)param_1 = 0;
  puVar1 = local_1c;
  uVar2 = (uint)local_18;
  if (local_18 == (undefined4 *)0x0) {
    puVar1 = (uint *)"unknown error";
    uVar2 = 0xd;
  }
  FUN_10008e70(param_1,puVar1,uVar2);
  LocalFree(local_1c);
  ExceptionList = local_10;
  FUN_1002e315(local_14 ^ (uint)&stack0xfffffffc);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_10009f50 @ 10009f50