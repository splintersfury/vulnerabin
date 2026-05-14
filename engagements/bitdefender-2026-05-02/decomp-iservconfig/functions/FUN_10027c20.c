void __fastcall FUN_10027c20(int *param_1)

{
  int *piVar1;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  puStack_c = &LAB_1004dd10;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  local_8 = 0;
  piVar1 = (int *)*param_1;
  if (piVar1 != (int *)0x0) {
    (**(code **)(*piVar1 + 8))(piVar1,DAT_10069054 ^ (uint)&stack0xfffffffc);
  }
  ExceptionList = local_10;
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_10027c70 @ 10027c70