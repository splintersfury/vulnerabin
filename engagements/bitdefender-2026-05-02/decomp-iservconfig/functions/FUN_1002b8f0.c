int * __fastcall FUN_1002b8f0(int *param_1)

{
  int iVar1;
  int iVar2;
  int *piVar3;
  short *psVar4;
  ushort *puVar5;
  short sVar6;
  ushort uVar7;
  undefined4 *puVar8;
  void *this;
  int iVar9;
  uint uVar10;
  int *piVar11;
  int iVar12;
  int iVar13;
  bool bVar14;
  uint uStack_44;
  int *local_34;
  char local_30;
  int *local_2c;
  int *local_28;
  int local_24;
  int *piStack_20;
  int local_1c;
  int *local_18;
  undefined1 *local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_10050c65;
  local_10 = ExceptionList;
  uStack_44 = DAT_10069054 ^ (uint)&stack0xfffffffc;
  local_14 = (undefined1 *)&uStack_44;
  ExceptionList = &local_10;
  iVar12 = 0;
  local_1c = 0;
  local_2c = param_1;
  local_18 = param_1;
  FUN_10007150(&local_34,param_1);
  local_8 = 0;
  if (local_30 == '\0') {
    uVar10 = 4;
    iVar12 = *(int *)(*param_1 + 4);
    *(undefined4 *)(iVar12 + 0x20 + (int)param_1) = 0;
    *(undefined4 *)(iVar12 + 0x24 + (int)param_1) = 0;
    this = (void *)(*(int *)(*param_1 + 4) + (int)param_1);
    if (*(int *)((int)this + 0x38) != 0) {
      uVar10 = 0;
    }
    FUN_10002bd0(this,uVar10 | *(uint *)(*(int *)(*param_1 + 4) + 0xc + (int)param_1),'\0');
    local_8 = 4;
    bVar14 = ___uncaught_exception();
    if (!bVar14) {
      FUN_10007e90(local_34);
    }
    local_8 = CONCAT31(local_8._1_3_,5);
    piVar11 = *(int **)(*(int *)(*local_34 + 4) + 0x38 + (int)local_34);
    if (piVar11 != (int *)0x0) {
      (**(code **)(*piVar11 + 8))();
    }
    ExceptionList = local_10;
    return param_1;
  }
  piStack_20 = *(int **)(*(int *)(*(int *)(*param_1 + 4) + 0x30 + (int)param_1) + 4);
  (**(code **)(*piStack_20 + 4))();
  local_8 = CONCAT31(local_8._1_3_,1);
  local_28 = (int *)FUN_10006410((_Facet_base *)&local_24);
  if ((piStack_20 != (int *)0x0) &&
     (puVar8 = (undefined4 *)(**(code **)(*piStack_20 + 8))(), puVar8 != (undefined4 *)0x0)) {
    (**(code **)*puVar8)(1);
  }
  iVar9 = *local_18;
  iVar1 = *(int *)(iVar9 + 4);
  iVar2 = *(int *)(iVar1 + 0x24 + (int)local_18);
  uVar10 = *(uint *)(iVar1 + 0x20 + (int)local_18);
  if ((iVar2 < 1) && ((iVar2 < 0 || (uVar10 < 2)))) {
    local_24 = 0;
    piStack_20 = (int *)0x0;
    piVar11 = piStack_20;
    iVar13 = local_24;
  }
  else {
    iVar13 = uVar10 - 1;
    piVar11 = (int *)(iVar2 - (uint)(uVar10 == 0));
  }
  local_8 = CONCAT31(local_8._1_3_,2);
  if ((*(uint *)(iVar1 + 0x14 + (int)local_18) & 0x1c0) == 0x40) {
LAB_1002ba32:
    iVar12 = 0;
    piStack_20 = *(int **)(*(int *)(iVar9 + 4) + 0x38 + (int)local_18);
    uVar7 = (**(code **)(*local_28 + 0x30))(0x3a);
    local_28 = (int *)(uint)uVar7;
    if ((*(int *)piStack_20[8] == 0) || (*(int *)piStack_20[0xc] < 1)) {
      uVar7 = (**(code **)(*piStack_20 + 0xc))(local_28);
    }
    else {
      *(int *)piStack_20[0xc] = *(int *)piStack_20[0xc] + -1;
      puVar5 = *(ushort **)piStack_20[8];
      *(ushort **)piStack_20[8] = puVar5 + 1;
      *puVar5 = uVar7;
    }
    if (uVar7 == 0xffff) {
      iVar12 = 4;
    }
    while (((local_1c = iVar12, iVar12 == 0 && (-1 < (int)piVar11)) &&
           ((0 < (int)piVar11 || (iVar13 != 0))))) {
      piVar3 = *(int **)(*(int *)(*local_18 + 4) + 0x38 + (int)local_18);
      sVar6 = *(short *)(*(int *)(*local_18 + 4) + 0x40 + (int)local_18);
      if (*(int *)piVar3[8] == 0) {
LAB_1002bade:
        sVar6 = (**(code **)(*piVar3 + 0xc))(sVar6);
      }
      else {
        iVar12 = *(int *)piVar3[0xc];
        if (iVar12 < 1) goto LAB_1002bade;
        *(int *)piVar3[0xc] = iVar12 + -1;
        psVar4 = *(short **)piVar3[8];
        *(short **)piVar3[8] = psVar4 + 1;
        *psVar4 = sVar6;
      }
      bVar14 = iVar13 != 0;
      iVar13 = iVar13 + -1;
      iVar12 = 4;
      piVar11 = (int *)((int)piVar11 + (bVar14 - 1));
      if (sVar6 != -1) {
        iVar12 = 0;
      }
    }
  }
  else {
    while (iVar12 == 0) {
      if (((int)piVar11 < 0) || (((int)piVar11 < 1 && (iVar13 == 0)))) {
        iVar9 = *local_18;
        goto LAB_1002ba32;
      }
      piVar3 = *(int **)(*(int *)(*local_18 + 4) + 0x38 + (int)local_18);
      sVar6 = *(short *)(*(int *)(*local_18 + 4) + 0x40 + (int)local_18);
      if (*(int *)piVar3[8] == 0) {
LAB_1002ba05:
        sVar6 = (**(code **)(*piVar3 + 0xc))(sVar6);
      }
      else {
        iVar12 = *(int *)piVar3[0xc];
        if (iVar12 < 1) goto LAB_1002ba05;
        *(int *)piVar3[0xc] = iVar12 + -1;
        psVar4 = *(short **)piVar3[8];
        *(short **)piVar3[8] = psVar4 + 1;
        *psVar4 = sVar6;
      }
      bVar14 = iVar13 != 0;
      iVar13 = iVar13 + -1;
      iVar12 = 4;
      piVar11 = (int *)((int)piVar11 + (bVar14 - 1));
      local_1c = iVar12;
      if (sVar6 != -1) {
        iVar12 = 0;
        local_1c = iVar12;
      }
    }
  }
  piVar11 = (int *)FUN_1002bb25();
  return piVar11;
}


// FUNCTION_END

// FUNCTION_START: Catch_All@1002bb06 @ 1002bb06