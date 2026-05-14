void __fastcall FUN_10023550(undefined1 *param_1)

{
  uint uVar1;
  undefined4 *this;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_1004ffcd;
  local_10 = ExceptionList;
  uVar1 = DAT_10069054 ^ (uint)&stack0xfffffffc;
  ExceptionList = &local_10;
  *(undefined8 *)(param_1 + 8) = 0;
  *param_1 = 3;
  this = (undefined4 *)operator_new(0x18);
  local_8 = 0;
  *this = 0;
  this[4] = 0;
  this[5] = 0xf;
  FUN_10008e70(this,(uint *)&DAT_1005fdb0,4);
  *(undefined4 **)(param_1 + 8) = this;
  *(undefined1 **)(param_1 + 0x10) = param_1;
  param_1[0x14] = 1;
  ExceptionList = local_10;
  FUN_1002e315(uVar1 ^ (uint)&stack0xfffffffc);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_10023600 @ 10023600