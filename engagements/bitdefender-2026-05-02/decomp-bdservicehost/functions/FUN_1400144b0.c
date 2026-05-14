longlong * FUN_1400144b0(longlong *param_1,undefined1 *param_2)

{
  int iVar1;
  short *psVar2;
  bool bVar3;
  short sVar4;
  undefined8 uVar5;
  longlong lVar6;
  longlong lVar7;
  uint uVar8;
  longlong lVar9;
  longlong lVar10;
  uint uVar11;
  undefined4 uVar12;
  longlong *plVar13;
  longlong *local_50;
  char local_48;
  undefined1 local_40 [8];
  longlong local_38;
  
  lVar7 = 0;
  uVar12 = 0;
  lVar9 = -1;
  do {
    lVar9 = lVar9 + 1;
  } while (param_2[lVar9] != '\0');
  lVar6 = *(longlong *)((longlong)*(int *)(*param_1 + 4) + 0x28 + (longlong)param_1);
  lVar10 = lVar7;
  if ((0 < lVar6) && (lVar9 < lVar6)) {
    lVar10 = lVar6 - lVar9;
  }
  plVar13 = param_1;
  FUN_14000ff70(&local_50,param_1);
  if (local_48 != '\0') {
    local_38 = *(longlong *)
                (*(longlong *)((longlong)*(int *)(*param_1 + 4) + 0x40 + (longlong)param_1) + 8);
    (*(code *)PTR__guard_dispatch_icall_14005b538)();
    uVar5 = FUN_140013c80((longlong)local_40);
    if ((local_38 != 0) && (lVar6 = (*(code *)PTR__guard_dispatch_icall_14005b538)(), lVar6 != 0)) {
      (*(code *)PTR__guard_dispatch_icall_14005b538)(lVar6,1);
    }
    if ((*(uint *)((longlong)*(int *)(*param_1 + 4) + 0x18 + (longlong)param_1) & 0x1c0) != 0x40) {
      for (; 0 < lVar10; lVar10 = lVar10 + -1) {
        lVar6 = *(longlong *)((longlong)*(int *)(*param_1 + 4) + 0x48 + (longlong)param_1);
        sVar4 = *(short *)((longlong)*(int *)(*param_1 + 4) + 0x58 + (longlong)param_1);
        if (**(longlong **)(lVar6 + 0x40) == 0) {
LAB_1400145f3:
          sVar4 = (*(code *)PTR__guard_dispatch_icall_14005b538)(lVar6,sVar4);
        }
        else {
          iVar1 = **(int **)(lVar6 + 0x58);
          if (iVar1 < 1) goto LAB_1400145f3;
          **(int **)(lVar6 + 0x58) = iVar1 + -1;
          psVar2 = (short *)**(longlong **)(lVar6 + 0x40);
          **(longlong **)(lVar6 + 0x40) = (longlong)(psVar2 + 1);
          *psVar2 = sVar4;
        }
        if (sVar4 == -1) {
          lVar7 = 4;
          uVar12 = 4;
          break;
        }
      }
    }
    do {
      uVar8 = (uint)lVar7;
      if (uVar8 != 0) goto LAB_140014738;
      if (lVar9 < 1) goto LAB_1400146d0;
      lVar7 = *(longlong *)((longlong)*(int *)(*param_1 + 4) + 0x48 + (longlong)param_1);
      sVar4 = (*(code *)PTR__guard_dispatch_icall_14005b538)(uVar5,*param_2);
      if (**(longlong **)(lVar7 + 0x40) == 0) {
LAB_140014694:
        sVar4 = (*(code *)PTR__guard_dispatch_icall_14005b538)(lVar7,sVar4);
      }
      else {
        iVar1 = **(int **)(lVar7 + 0x58);
        if (iVar1 < 1) goto LAB_140014694;
        **(int **)(lVar7 + 0x58) = iVar1 + -1;
        psVar2 = (short *)**(longlong **)(lVar7 + 0x40);
        **(longlong **)(lVar7 + 0x40) = (longlong)(psVar2 + 1);
        *psVar2 = sVar4;
      }
      lVar9 = lVar9 + -1;
      param_2 = param_2 + 1;
      lVar7 = 4;
      if (sVar4 != -1) {
        lVar7 = 0;
      }
      uVar12 = (undefined4)lVar7;
    } while( true );
  }
  uVar8 = 4;
LAB_14001475e:
  lVar7 = (longlong)*(int *)(*param_1 + 4) + (longlong)param_1;
  uVar11 = 4;
  if (*(longlong *)(lVar7 + 0x48) != 0) {
    uVar11 = 0;
  }
  FUN_140002cd0(lVar7,uVar11 | uVar8 | *(uint *)(lVar7 + 0x10),'\0');
  bVar3 = __uncaught_exception();
  if (!bVar3) {
    FUN_140011c80(local_50);
  }
  if (*(longlong *)((longlong)*(int *)(*local_50 + 4) + 0x48 + (longlong)local_50) != 0) {
    (*(code *)PTR__guard_dispatch_icall_14005b538)();
  }
  return param_1;
LAB_1400146d0:
  if (lVar10 < 1) goto LAB_140014738;
  lVar7 = *(longlong *)((longlong)*(int *)(*param_1 + 4) + 0x48 + (longlong)param_1);
  sVar4 = *(short *)((longlong)*(int *)(*param_1 + 4) + 0x58 + (longlong)param_1);
  if (**(longlong **)(lVar7 + 0x40) == 0) {
LAB_140014713:
    sVar4 = (*(code *)PTR__guard_dispatch_icall_14005b538)
                      (lVar7,sVar4,lVar7,sVar4,uVar12,plVar13,uVar5);
  }
  else {
    iVar1 = **(int **)(lVar7 + 0x58);
    if (iVar1 < 1) goto LAB_140014713;
    **(int **)(lVar7 + 0x58) = iVar1 + -1;
    psVar2 = (short *)**(longlong **)(lVar7 + 0x40);
    **(longlong **)(lVar7 + 0x40) = (longlong)(psVar2 + 1);
    *psVar2 = sVar4;
  }
  if (sVar4 == -1) {
    uVar8 = 4;
    goto LAB_140014738;
  }
  lVar10 = lVar10 + -1;
  goto LAB_1400146d0;
LAB_140014738:
  *(undefined8 *)((longlong)*(int *)(*param_1 + 4) + 0x28 + (longlong)param_1) = 0;
  goto LAB_14001475e;
}


// FUNCTION_END

// FUNCTION_START: FUN_1400147e0 @ 1400147e0