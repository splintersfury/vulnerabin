longlong * FUN_1400147e0(longlong *param_1,undefined8 param_2,ulonglong param_3)

{
  int iVar1;
  short *psVar2;
  bool bVar3;
  short sVar4;
  ulonglong uVar5;
  longlong lVar6;
  longlong lVar7;
  uint uVar8;
  longlong lVar9;
  uint uVar10;
  undefined4 uVar11;
  longlong *plVar12;
  longlong *local_48;
  char local_40;
  
  lVar9 = 0;
  uVar11 = 0;
  uVar5 = *(ulonglong *)((longlong)*(int *)(*param_1 + 4) + 0x28 + (longlong)param_1);
  lVar6 = lVar9;
  if ((0 < (longlong)uVar5) && (param_3 < uVar5)) {
    lVar6 = uVar5 - param_3;
  }
  plVar12 = param_1;
  FUN_14000ff70(&local_48,param_1);
  if (local_40 == '\0') {
    uVar8 = 4;
  }
  else {
    lVar7 = *param_1;
    if ((*(uint *)((longlong)*(int *)(lVar7 + 4) + 0x18 + (longlong)param_1) & 0x1c0) != 0x40) {
      for (; lVar6 != 0; lVar6 = lVar6 + -1) {
        lVar7 = *(longlong *)((longlong)*(int *)(*param_1 + 4) + 0x48 + (longlong)param_1);
        sVar4 = *(short *)((longlong)*(int *)(*param_1 + 4) + 0x58 + (longlong)param_1);
        if (**(longlong **)(lVar7 + 0x40) == 0) {
LAB_1400148b7:
          sVar4 = (*(code *)PTR__guard_dispatch_icall_14005b538)
                            (lVar7,sVar4,lVar7,sVar4,uVar11,plVar12);
        }
        else {
          iVar1 = **(int **)(lVar7 + 0x58);
          if (iVar1 < 1) goto LAB_1400148b7;
          **(int **)(lVar7 + 0x58) = iVar1 + -1;
          psVar2 = (short *)**(longlong **)(lVar7 + 0x40);
          **(longlong **)(lVar7 + 0x40) = (longlong)(psVar2 + 1);
          *psVar2 = sVar4;
        }
        if (sVar4 == -1) {
          lVar9 = 4;
          uVar11 = 4;
          goto LAB_1400148e3;
        }
      }
      lVar7 = *param_1;
    }
    uVar5 = (*(code *)PTR__guard_dispatch_icall_14005b538)
                      (*(undefined8 *)((longlong)*(int *)(lVar7 + 4) + 0x48 + (longlong)param_1),
                       param_2);
    if (uVar5 == param_3) {
LAB_1400148e3:
      do {
        uVar8 = (uint)lVar9;
        if (lVar6 == 0) goto LAB_140014960;
        lVar7 = *(longlong *)((longlong)*(int *)(*param_1 + 4) + 0x48 + (longlong)param_1);
        sVar4 = *(short *)((longlong)*(int *)(*param_1 + 4) + 0x58 + (longlong)param_1);
        if (**(longlong **)(lVar7 + 0x40) == 0) {
LAB_14001496e:
          sVar4 = (*(code *)PTR__guard_dispatch_icall_14005b538)(lVar7,sVar4,lVar7,sVar4,uVar11);
        }
        else {
          iVar1 = **(int **)(lVar7 + 0x58);
          if (iVar1 < 1) goto LAB_14001496e;
          **(int **)(lVar7 + 0x58) = iVar1 + -1;
          psVar2 = (short *)**(longlong **)(lVar7 + 0x40);
          **(longlong **)(lVar7 + 0x40) = (longlong)(psVar2 + 1);
          *psVar2 = sVar4;
        }
        if (sVar4 == -1) {
          uVar8 = 4;
          goto LAB_140014960;
        }
        lVar6 = lVar6 + -1;
      } while( true );
    }
    uVar8 = 4;
LAB_140014960:
    *(undefined8 *)((longlong)*(int *)(*param_1 + 4) + 0x28 + (longlong)param_1) = 0;
  }
  lVar6 = (longlong)*(int *)(*param_1 + 4) + (longlong)param_1;
  uVar10 = 4;
  if (*(longlong *)(lVar6 + 0x48) != 0) {
    uVar10 = 0;
  }
  FUN_140002cd0(lVar6,uVar10 | uVar8 | *(uint *)(lVar6 + 0x10),'\0');
  bVar3 = __uncaught_exception();
  if (!bVar3) {
    FUN_140011c80(local_48);
  }
  if (*(longlong *)((longlong)*(int *)(*local_48 + 4) + 0x48 + (longlong)local_48) != 0) {
    (*(code *)PTR__guard_dispatch_icall_14005b538)();
  }
  return param_1;
}


// FUNCTION_END

// FUNCTION_START: FUN_140014a20 @ 140014a20