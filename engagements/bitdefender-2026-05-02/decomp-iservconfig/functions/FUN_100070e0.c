void __fastcall FUN_100070e0(int *param_1)

{
  int *piVar1;
  bool bVar2;
  uint uVar3;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_1004db00;
  local_10 = ExceptionList;
  uVar3 = DAT_10069054 ^ (uint)&stack0xfffffffc;
  ExceptionList = &local_10;
  bVar2 = ___uncaught_exception();
  if (!bVar2) {
    FUN_10007e90((int *)*param_1);
  }
  local_8 = 0;
  piVar1 = *(int **)(*(int *)(*(int *)*param_1 + 4) + 0x38 + *param_1);
  if (piVar1 != (int *)0x0) {
    (**(code **)(*piVar1 + 8))(uVar3);
  }
  ExceptionList = local_10;
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_10007150 @ 10007150