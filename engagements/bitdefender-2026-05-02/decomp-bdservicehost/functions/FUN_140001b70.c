undefined8 FUN_140001b70(longlong *param_1,undefined4 param_2,int *param_3)

{
  int *piVar1;
  uint7 uVar2;
  undefined1 local_18 [16];
  
  piVar1 = (int *)(*(code *)PTR__guard_dispatch_icall_14005b538)(param_1,local_18,param_2);
  uVar2 = (uint7)((ulonglong)piVar1 >> 8);
  if ((*(longlong *)(*(longlong *)(piVar1 + 2) + 8) == *(longlong *)(*(longlong *)(param_3 + 2) + 8)
      ) && (*piVar1 == *param_3)) {
    return CONCAT71(uVar2,1);
  }
  return (ulonglong)uVar2 << 8;
}


// FUNCTION_END

// FUNCTION_START: FUN_140001bc0 @ 140001bc0