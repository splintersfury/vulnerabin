longlong * FUN_140012a30(longlong *param_1,longlong param_2)

{
  int iVar1;
  short *psVar2;
  bool bVar3;
  short sVar4;
  longlong lVar5;
  uint uVar6;
  longlong lVar7;
  uint uVar8;
  longlong lVar9;
  undefined4 uVar10;
  longlong *plVar11;
  longlong *local_38;
  char local_30;
  
  lVar7 = 0;
  uVar8 = 0;
  uVar10 = 0;
  lVar9 = -1;
  do {
    lVar9 = lVar9 + 1;
  } while (*(short *)(param_2 + lVar9 * 2) != 0);
  lVar5 = *(longlong *)((longlong)*(int *)(*param_1 + 4) + 0x28 + (longlong)param_1);
  if ((0 < lVar5) && (lVar9 < lVar5)) {
    lVar7 = lVar5 - lVar9;
  }
  plVar11 = param_1;
  FUN_14000ff70(&local_38,param_1);
  if (local_30 == '\0') {
    uVar8 = 4;
  }
  else {
    lVar5 = *param_1;
    if ((*(uint *)((longlong)*(int *)(lVar5 + 4) + 0x18 + (longlong)param_1) & 0x1c0) != 0x40) {
      for (; 0 < lVar7; lVar7 = lVar7 + -1) {
        lVar5 = *(longlong *)((longlong)*(int *)(*param_1 + 4) + 0x48 + (longlong)param_1);
        sVar4 = *(short *)((longlong)*(int *)(*param_1 + 4) + 0x58 + (longlong)param_1);
        if (**(longlong **)(lVar5 + 0x40) == 0) {
LAB_140012b13:
          sVar4 = (*(code *)PTR__guard_dispatch_icall_14005b538)(lVar5,sVar4);
        }
        else {
          iVar1 = **(int **)(lVar5 + 0x58);
          if (iVar1 < 1) goto LAB_140012b13;
          **(int **)(lVar5 + 0x58) = iVar1 + -1;
          psVar2 = (short *)**(longlong **)(lVar5 + 0x40);
          **(longlong **)(lVar5 + 0x40) = (longlong)(psVar2 + 1);
          *psVar2 = sVar4;
        }
        if (sVar4 == -1) {
          uVar8 = 4;
          goto LAB_140012bef;
        }
      }
      lVar5 = *param_1;
    }
    lVar5 = (*(code *)PTR__guard_dispatch_icall_14005b538)
                      (*(undefined8 *)((longlong)*(int *)(lVar5 + 4) + 0x48 + (longlong)param_1),
                       param_2);
    if (lVar5 == lVar9) {
      for (; 0 < lVar7; lVar7 = lVar7 + -1) {
        lVar9 = *(longlong *)((longlong)*(int *)(*param_1 + 4) + 0x48 + (longlong)param_1);
        sVar4 = *(short *)((longlong)*(int *)(*param_1 + 4) + 0x58 + (longlong)param_1);
        if (**(longlong **)(lVar9 + 0x40) == 0) {
LAB_140012bba:
          sVar4 = (*(code *)PTR__guard_dispatch_icall_14005b538)
                            (lVar9,sVar4,lVar9,sVar4,uVar10,plVar11);
        }
        else {
          iVar1 = **(int **)(lVar9 + 0x58);
          if (iVar1 < 1) goto LAB_140012bba;
          **(int **)(lVar9 + 0x58) = iVar1 + -1;
          psVar2 = (short *)**(longlong **)(lVar9 + 0x40);
          **(longlong **)(lVar9 + 0x40) = (longlong)(psVar2 + 1);
          *psVar2 = sVar4;
        }
        if (sVar4 == -1) {
          uVar8 = 4;
          break;
        }
      }
    }
    else {
      uVar8 = 4;
    }
LAB_140012bef:
    *(undefined8 *)((longlong)*(int *)(*param_1 + 4) + 0x28 + (longlong)param_1) = 0;
  }
  lVar7 = (longlong)*(int *)(*param_1 + 4) + (longlong)param_1;
  uVar6 = 4;
  if (*(longlong *)(lVar7 + 0x48) != 0) {
    uVar6 = 0;
  }
  FUN_140002cd0(lVar7,uVar6 | uVar8 | *(uint *)(lVar7 + 0x10),'\0');
  bVar3 = __uncaught_exception();
  if (!bVar3) {
    FUN_140011c80(local_38);
  }
  if (*(longlong *)((longlong)*(int *)(*local_38 + 4) + 0x48 + (longlong)local_38) != 0) {
    (*(code *)PTR__guard_dispatch_icall_14005b538)();
  }
  return param_1;
}


// FUNCTION_END

// FUNCTION_START: FUN_140012c90 @ 140012c90