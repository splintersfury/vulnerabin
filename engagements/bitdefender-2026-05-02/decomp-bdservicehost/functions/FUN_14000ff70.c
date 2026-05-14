undefined8 * FUN_14000ff70(undefined8 *param_1,longlong *param_2)

{
  longlong *plVar1;
  longlong lVar2;
  bool bVar3;
  int iVar4;
  longlong lVar5;
  longlong *local_18;
  char local_10;
  
  *param_1 = param_2;
  lVar5 = *param_2;
  if (*(longlong *)((longlong)*(int *)(lVar5 + 4) + 0x48 + (longlong)param_2) != 0) {
    (*(code *)PTR__guard_dispatch_icall_14005b538)();
    lVar5 = *param_2;
  }
  if (*(int *)((longlong)*(int *)(lVar5 + 4) + 0x10 + (longlong)param_2) == 0) {
    plVar1 = *(longlong **)((longlong)*(int *)(lVar5 + 4) + 0x50 + (longlong)param_2);
    if ((plVar1 == (longlong *)0x0) || (plVar1 == param_2)) {
      bVar3 = true;
    }
    else {
      lVar2 = *(longlong *)((longlong)*(int *)(*plVar1 + 4) + 0x48 + (longlong)plVar1);
      if (lVar2 != 0) {
        FUN_14000ff70(&local_18,plVar1);
        if (local_10 != '\0') {
          iVar4 = (*(code *)PTR__guard_dispatch_icall_14005b538)(lVar2);
          if (iVar4 == -1) {
            lVar5 = (longlong)*(int *)(*plVar1 + 4) + (longlong)plVar1;
            FUN_140002cd0(lVar5,*(uint *)(lVar5 + 0x10) | 4,'\0');
          }
        }
        bVar3 = __uncaught_exception();
        if (!bVar3) {
          FUN_140011c80(local_18);
        }
        if (*(longlong *)((longlong)*(int *)(*local_18 + 4) + 0x48 + (longlong)local_18) != 0) {
          (*(code *)PTR__guard_dispatch_icall_14005b538)();
        }
        lVar5 = *param_2;
      }
      bVar3 = *(int *)((longlong)*(int *)(lVar5 + 4) + 0x10 + (longlong)param_2) == 0;
    }
  }
  else {
    bVar3 = false;
  }
  *(bool *)(param_1 + 1) = bVar3;
  return param_1;
}


// FUNCTION_END

// FUNCTION_START: FUN_1400100a0 @ 1400100a0