void FUN_140011c80(longlong *param_1)

{
  int iVar1;
  longlong lVar2;
  
  if ((*(int *)((longlong)*(int *)(*param_1 + 4) + 0x10 + (longlong)param_1) == 0) &&
     ((*(byte *)((longlong)*(int *)(*param_1 + 4) + 0x18 + (longlong)param_1) & 2) != 0)) {
    iVar1 = (*(code *)PTR__guard_dispatch_icall_14005b538)();
    if (iVar1 == -1) {
      lVar2 = (longlong)*(int *)(*param_1 + 4) + (longlong)param_1;
      FUN_140002cd0(lVar2,*(uint *)(lVar2 + 0x10) | 4,'\0');
    }
  }
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_140011ce0 @ 140011ce0