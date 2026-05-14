ulonglong FUN_14001c460(longlong *param_1)

{
  byte *pbVar1;
  ulonglong uVar2;
  
  pbVar1 = *(byte **)param_1[7];
  if ((pbVar1 != (byte *)0x0) && (pbVar1 < pbVar1 + *(int *)param_1[10])) {
    return (ulonglong)*pbVar1;
  }
  uVar2 = (*(code *)PTR__guard_dispatch_icall_14005b538)();
  if ((int)uVar2 == -1) {
    return uVar2;
  }
  (*(code *)PTR__guard_dispatch_icall_14005b538)(param_1,uVar2 & 0xffffffff);
  return uVar2 & 0xffffffff;
}


// FUNCTION_END

// FUNCTION_START: FUN_14001c4e0 @ 14001c4e0