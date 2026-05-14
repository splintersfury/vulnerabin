void __fastcall FUN_10027bb0(int *param_1)

{
  int *piVar1;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  puStack_c = &LAB_10050470;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  local_8 = 0;
  piVar1 = (int *)param_1[1];
  if (piVar1 != (int *)0x0) {
    (**(code **)(*piVar1 + 8))(piVar1,DAT_10069054 ^ (uint)&stack0xfffffffc);
  }
  local_8 = 1;
  piVar1 = (int *)*param_1;
  if (piVar1 != (int *)0x0) {
    (**(code **)(*piVar1 + 8))(piVar1);
  }
  ExceptionList = local_10;
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_10027c20 @ 10027c20