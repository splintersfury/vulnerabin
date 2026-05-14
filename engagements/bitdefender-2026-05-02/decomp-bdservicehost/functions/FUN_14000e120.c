undefined2 FUN_14000e120(longlong *param_1)

{
  undefined2 *puVar1;
  short sVar2;
  
  sVar2 = (*(code *)PTR__guard_dispatch_icall_14005b538)();
  if (sVar2 == -1) {
    return 0xffff;
  }
  *(int *)param_1[10] = *(int *)param_1[10] + -1;
  puVar1 = *(undefined2 **)param_1[7];
  *(undefined2 **)param_1[7] = puVar1 + 1;
  return *puVar1;
}


// FUNCTION_END

// FUNCTION_START: FUN_14000e170 @ 14000e170