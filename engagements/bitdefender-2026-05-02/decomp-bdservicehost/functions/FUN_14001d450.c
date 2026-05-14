void FUN_14001d450(longlong *param_1)

{
  longlong *plVar1;
  
  FUN_14001d5f0((longlong)(param_1 + 9));
  plVar1 = (longlong *)param_1[7];
  if (plVar1 != (longlong *)0x0) {
    (*(code *)PTR__guard_dispatch_icall_14005b538)(plVar1,plVar1 != param_1);
    param_1[7] = 0;
  }
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_14001d490 @ 14001d490