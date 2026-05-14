void FUN_140014df0(longlong *param_1,longlong *param_2)

{
  longlong *plVar1;
  longlong lVar2;
  undefined1 auStack_78 [32];
  longlong local_58 [7];
  longlong *local_20;
  ulonglong local_18;
  
  local_18 = DAT_14007a060 ^ (ulonglong)auStack_78;
  plVar1 = (longlong *)param_1[7];
  if ((plVar1 != param_1) && ((longlong *)param_2[7] != param_2)) {
    param_1[7] = param_2[7];
    param_2[7] = (longlong)plVar1;
    goto LAB_140014f3d;
  }
  local_20 = (longlong *)0x0;
  if (plVar1 != (longlong *)0x0) {
    if (plVar1 == param_1) {
      local_20 = (longlong *)(*(code *)PTR__guard_dispatch_icall_14005b538)(plVar1,local_58);
      plVar1 = (longlong *)param_1[7];
      if (plVar1 == (longlong *)0x0) goto LAB_140014e93;
      (*(code *)PTR__guard_dispatch_icall_14005b538)(plVar1,plVar1 != param_1);
      plVar1 = local_20;
    }
    local_20 = plVar1;
    param_1[7] = 0;
  }
LAB_140014e93:
  plVar1 = (longlong *)param_2[7];
  if (plVar1 != (longlong *)0x0) {
    if (plVar1 == param_2) {
      lVar2 = (*(code *)PTR__guard_dispatch_icall_14005b538)(plVar1,param_1);
      param_1[7] = lVar2;
      plVar1 = (longlong *)param_2[7];
      if (plVar1 == (longlong *)0x0) goto LAB_140014ee7;
      (*(code *)PTR__guard_dispatch_icall_14005b538)(plVar1,plVar1 != param_2);
    }
    else {
      param_1[7] = (longlong)plVar1;
    }
    param_2[7] = 0;
  }
LAB_140014ee7:
  if (local_20 != (longlong *)0x0) {
    if (local_20 == local_58) {
      lVar2 = (*(code *)PTR__guard_dispatch_icall_14005b538)(local_20,param_2);
      param_2[7] = lVar2;
      if (local_20 != (longlong *)0x0) {
        (*(code *)PTR__guard_dispatch_icall_14005b538)
                  (local_20,CONCAT71((int7)((ulonglong)local_58 >> 8),local_20 != local_58));
      }
    }
    else {
      param_2[7] = (longlong)local_20;
    }
  }
LAB_140014f3d:
  FUN_14002f160(local_18 ^ (ulonglong)auStack_78);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_140014f60 @ 140014f60