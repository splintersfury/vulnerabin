void __fastcall FUN_1000a2a0(int param_1)

{
  void *local_10;
  undefined1 *puStack_c;
  undefined4 uStack_8;
  
  uStack_8 = 0xffffffff;
  puStack_c = &LAB_1004dff0;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  (**(code **)(*(int *)(param_1 + 0x10) + 4))(DAT_10069054 ^ (uint)&stack0xfffffffc);
  ExceptionList = local_10;
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_1000a2e0 @ 1000a2e0