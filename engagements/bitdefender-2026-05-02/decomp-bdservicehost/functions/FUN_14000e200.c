longlong * FUN_14000e200(longlong *param_1,undefined4 param_2)

{
  bool bVar1;
  undefined8 uVar2;
  longlong lVar3;
  uint uVar4;
  uint uVar5;
  longlong *local_48;
  char local_40;
  uint local_38 [2];
  longlong lStack_30;
  char local_28 [16];
  
  FUN_14000ff70(&local_48,param_1);
  uVar5 = 0;
  if (local_40 != '\0') {
    lStack_30 = *(longlong *)
                 (*(longlong *)((longlong)*(int *)(*param_1 + 4) + 0x40 + (longlong)param_1) + 8);
    (*(code *)PTR__guard_dispatch_icall_14005b538)();
    uVar2 = FUN_140012ef0((longlong)local_38);
    if ((lStack_30 != 0) && (lVar3 = (*(code *)PTR__guard_dispatch_icall_14005b538)(), lVar3 != 0))
    {
      (*(code *)PTR__guard_dispatch_icall_14005b538)(lVar3,1);
    }
    lVar3 = (longlong)*(int *)(*param_1 + 4) + (longlong)param_1;
    lStack_30 = *(undefined8 *)(lVar3 + 0x48);
    local_38[0] = local_38[0] & 0xffffff00;
    (*(code *)PTR__guard_dispatch_icall_14005b538)
              (uVar2,local_28,local_38,lVar3,*(undefined2 *)(lVar3 + 0x58),param_2);
    uVar5 = 0;
    if (local_28[0] != '\0') {
      uVar5 = 4;
    }
  }
  lVar3 = (longlong)*(int *)(*param_1 + 4) + (longlong)param_1;
  uVar4 = 4;
  if (*(longlong *)(lVar3 + 0x48) != 0) {
    uVar4 = 0;
  }
  FUN_140002cd0(lVar3,uVar4 | uVar5 | *(uint *)(lVar3 + 0x10),'\0');
  bVar1 = __uncaught_exception();
  if (!bVar1) {
    FUN_140011c80(local_48);
  }
  if (*(longlong *)((longlong)*(int *)(*local_48 + 4) + 0x48 + (longlong)local_48) != 0) {
    (*(code *)PTR__guard_dispatch_icall_14005b538)();
  }
  return param_1;
}


// FUNCTION_END

// FUNCTION_START: FUN_14000e3c0 @ 14000e3c0