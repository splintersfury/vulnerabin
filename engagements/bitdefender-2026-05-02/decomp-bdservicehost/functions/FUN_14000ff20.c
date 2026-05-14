void FUN_14000ff20(longlong *param_1)

{
  bool bVar1;
  
  bVar1 = __uncaught_exception();
  if (!bVar1) {
    FUN_140011c80((longlong *)*param_1);
  }
  if (*(longlong *)((longlong)*(int *)(*(longlong *)*param_1 + 4) + 0x48 + *param_1) != 0) {
    (*(code *)PTR__guard_dispatch_icall_14005b538)();
  }
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_14000ff70 @ 14000ff70