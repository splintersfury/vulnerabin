ulonglong FUN_14001d220(longlong *param_1)

{
  byte *pbVar1;
  ulonglong uVar2;
  
  uVar2 = (*(code *)PTR__guard_dispatch_icall_14005b538)();
  if ((int)uVar2 == -1) {
    return uVar2;
  }
  *(int *)param_1[10] = *(int *)param_1[10] + -1;
  pbVar1 = *(byte **)param_1[7];
  *(byte **)param_1[7] = pbVar1 + 1;
  return (ulonglong)*pbVar1;
}


// FUNCTION_END

// FUNCTION_START: FUN_14001d260 @ 14001d260