undefined4 * __fastcall FUN_10027f40(undefined4 *param_1,uint *param_2)

{
  uint uVar1;
  uint *puVar2;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  puStack_c = &LAB_1005056e;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  local_8 = 0;
  *param_1 = 0;
  param_1[4] = 0;
  param_1[5] = 7;
  *(undefined2 *)param_1 = 0;
  FUN_10001d40(param_1,(uint *)L"ASSOCIATORS OF {Win32_DiskDrive.DeviceID=\'",0x2a);
  local_8 = 0;
  puVar2 = param_2;
  do {
    uVar1 = *puVar2;
    puVar2 = (uint *)((int)puVar2 + 2);
  } while ((short)uVar1 != 0);
  FUN_10005d60(param_1,param_2,(int)puVar2 - ((int)param_2 + 2) >> 1);
  FUN_10005d60(param_1,(uint *)L"\'} where AssocClass = Win32_DiskDriveToDiskPartition",0x34);
  ExceptionList = local_10;
  return param_1;
}


// FUNCTION_END

// FUNCTION_START: FUN_10027ff0 @ 10027ff0