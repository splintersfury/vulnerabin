int * __fastcall FUN_10024420(int *param_1,undefined4 *param_2)

{
  uint uVar1;
  bool bVar2;
  ushort uVar3;
  int *piVar4;
  ushort *puVar5;
  int iVar6;
  void *this;
  uint uVar7;
  undefined4 *puVar8;
  int iVar9;
  int iVar10;
  uint uStack_44;
  int *local_34;
  char local_30;
  int *local_2c;
  int local_28;
  undefined4 *local_24;
  ushort *local_20;
  ushort *local_1c;
  int *local_18;
  undefined1 *local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_1005011d;
  local_10 = ExceptionList;
  uStack_44 = DAT_10069054 ^ (uint)&stack0xfffffffc;
  local_14 = (undefined1 *)&uStack_44;
  ExceptionList = &local_10;
  puVar5 = (ushort *)*param_2;
  uVar7 = param_2[1] + 2;
  local_20 = puVar5 + param_2[1];
  if (puVar5 != local_20) {
    do {
      if ((*puVar5 == *(ushort *)(param_2 + 2)) || (*puVar5 == *(ushort *)((int)param_2 + 10))) {
        uVar7 = uVar7 + 1;
      }
      puVar5 = puVar5 + 1;
    } while (puVar5 != local_20);
  }
  iVar10 = 0;
  local_28 = 0;
  uVar1 = *(uint *)(*(int *)(*param_1 + 4) + 0x20 + (int)param_1);
  iVar9 = *(int *)(*(int *)(*param_1 + 4) + 0x24 + (int)param_1);
  if ((iVar9 < 0) || (((iVar9 < 1 && (uVar1 == 0)) || (uVar1 <= uVar7)))) {
    iVar9 = 0;
  }
  else {
    iVar9 = uVar1 - uVar7;
  }
  local_2c = param_1;
  local_24 = param_2;
  local_18 = param_1;
  FUN_10007150(&local_34,param_1);
  local_8 = 0;
  if (local_30 == '\0') {
    uVar7 = 4;
    this = (void *)(*(int *)(*param_1 + 4) + (int)param_1);
    if (*(int *)((int)this + 0x38) != 0) {
      uVar7 = 0;
    }
    FUN_10002bd0(this,uVar7 | *(uint *)(*(int *)(*param_1 + 4) + 0xc + (int)param_1) | 4,'\0');
    local_8 = 3;
    bVar2 = ___uncaught_exception();
    if (!bVar2) {
      FUN_10007e90(local_34);
    }
    local_8 = CONCAT31(local_8._1_3_,4);
    piVar4 = *(int **)(*(int *)(*local_34 + 4) + 0x38 + (int)local_34);
    if (piVar4 != (int *)0x0) {
      (**(code **)(*piVar4 + 8))();
    }
    ExceptionList = local_10;
    return param_1;
  }
  local_8 = 1;
  iVar6 = *param_1;
  if ((*(uint *)(*(int *)(iVar6 + 4) + 0x14 + (int)param_1) & 0x1c0) != 0x40) {
    for (; iVar9 != 0; iVar9 = iVar9 + -1) {
      piVar4 = *(int **)(*(int *)(*param_1 + 4) + 0x38 + (int)param_1);
      uVar3 = *(ushort *)(*(int *)(*param_1 + 4) + 0x40 + (int)param_1);
      local_1c = (ushort *)(uint)uVar3;
      if ((*(int *)piVar4[8] == 0) || (*(int *)piVar4[0xc] < 1)) {
        uVar3 = (**(code **)(*piVar4 + 0xc))(local_1c);
      }
      else {
        *(int *)piVar4[0xc] = *(int *)piVar4[0xc] + -1;
        puVar5 = *(ushort **)piVar4[8];
        *(ushort **)piVar4[8] = puVar5 + 1;
        *puVar5 = uVar3;
      }
      if (uVar3 == 0xffff) {
        iVar10 = 4;
        goto LAB_1002459c;
      }
    }
    iVar6 = *param_1;
  }
  piVar4 = *(int **)(*(int *)(iVar6 + 4) + 0x38 + (int)param_1);
  uVar3 = *(ushort *)(local_24 + 2);
  local_1c = (ushort *)(uint)uVar3;
  if ((*(int *)piVar4[8] == 0) || (*(int *)piVar4[0xc] < 1)) {
    uVar3 = (**(code **)(*piVar4 + 0xc))(local_1c);
  }
  else {
    *(int *)piVar4[0xc] = *(int *)piVar4[0xc] + -1;
    puVar5 = *(ushort **)piVar4[8];
    *(ushort **)piVar4[8] = puVar5 + 1;
    *puVar5 = uVar3;
  }
  if (uVar3 == 0xffff) {
    iVar10 = 4;
  }
LAB_1002459c:
  puVar8 = local_24;
  local_28 = iVar10;
  for (local_1c = (ushort *)*local_24; local_1c != local_20; local_1c = local_1c + 1) {
    if ((*local_1c == *(ushort *)(puVar8 + 2)) || (*local_1c == *(ushort *)((int)puVar8 + 10))) {
      if (iVar10 != 0) goto LAB_100246cf;
      piVar4 = *(int **)(*(int *)(*param_1 + 4) + 0x38 + (int)param_1);
      uVar3 = *(ushort *)((int)puVar8 + 10);
      local_18 = (int *)(uint)uVar3;
      if (*(int *)piVar4[8] == 0) {
LAB_10024647:
        uVar3 = (**(code **)(*piVar4 + 0xc))(local_18);
      }
      else {
        iVar6 = *(int *)piVar4[0xc];
        if (iVar6 < 1) goto LAB_10024647;
        *(int *)piVar4[0xc] = iVar6 + -1;
        puVar5 = *(ushort **)piVar4[8];
        *(ushort **)piVar4[8] = puVar5 + 1;
        *puVar5 = uVar3;
      }
      if (uVar3 == 0xffff) {
        iVar10 = 4;
        local_28 = 4;
        puVar8 = local_24;
        break;
      }
LAB_100245c7:
      piVar4 = *(int **)(*(int *)(*param_1 + 4) + 0x38 + (int)param_1);
      uVar3 = *local_1c;
      local_18 = (int *)(uint)uVar3;
      if (*(int *)piVar4[8] == 0) {
LAB_100246ac:
        uVar3 = (**(code **)(*piVar4 + 0xc))(local_18);
      }
      else {
        iVar6 = *(int *)piVar4[0xc];
        if (iVar6 < 1) goto LAB_100246ac;
        *(int *)piVar4[0xc] = iVar6 + -1;
        puVar5 = *(ushort **)piVar4[8];
        *(ushort **)piVar4[8] = puVar5 + 1;
        *puVar5 = uVar3;
      }
      puVar8 = local_24;
      if (uVar3 == 0xffff) {
        iVar10 = 4;
        local_28 = iVar10;
        break;
      }
    }
    else if (iVar10 == 0) goto LAB_100245c7;
LAB_100246cf:
  }
  if (iVar10 == 0) {
    uVar3 = *(ushort *)(puVar8 + 2);
    local_20 = (ushort *)(uint)uVar3;
    piVar4 = *(int **)(*(int *)(*param_1 + 4) + 0x38 + (int)param_1);
    if ((*(int *)piVar4[8] == 0) || (*(int *)piVar4[0xc] < 1)) {
      uVar3 = (**(code **)(*piVar4 + 0xc))(local_20);
    }
    else {
      *(int *)piVar4[0xc] = *(int *)piVar4[0xc] + -1;
      puVar5 = *(ushort **)piVar4[8];
      *(ushort **)piVar4[8] = puVar5 + 1;
      *puVar5 = uVar3;
    }
    if (uVar3 != 0xffff) {
      for (; iVar9 != 0; iVar9 = iVar9 + -1) {
        piVar4 = *(int **)(*(int *)(*param_1 + 4) + 0x38 + (int)param_1);
        uVar3 = *(ushort *)(*(int *)(*param_1 + 4) + 0x40 + (int)param_1);
        local_20 = (ushort *)(uint)uVar3;
        if ((*(int *)piVar4[8] == 0) || (*(int *)piVar4[0xc] < 1)) {
          uVar3 = (**(code **)(*piVar4 + 0xc))(local_20);
        }
        else {
          *(int *)piVar4[0xc] = *(int *)piVar4[0xc] + -1;
          puVar5 = *(ushort **)piVar4[8];
          *(ushort **)piVar4[8] = puVar5 + 1;
          *puVar5 = uVar3;
        }
        if (uVar3 == 0xffff) break;
      }
    }
  }
  iVar9 = *(int *)(*param_1 + 4);
  *(undefined4 *)(iVar9 + 0x20 + (int)param_1) = 0;
  *(undefined4 *)(iVar9 + 0x24 + (int)param_1) = 0;
  piVar4 = (int *)FUN_10024780();
  return piVar4;
}


// FUNCTION_END

// FUNCTION_START: Catch_All@10024761 @ 10024761