int * __fastcall FUN_10007f80(int *param_1,char *param_2)

{
  char cVar1;
  int iVar2;
  ushort *puVar3;
  int *piVar4;
  bool bVar5;
  ushort uVar6;
  undefined4 *puVar7;
  int *piVar8;
  char *pcVar9;
  void *this;
  uint uVar10;
  int iVar11;
  int iVar12;
  int iVar13;
  uint uStack_5c;
  undefined8 local_44;
  _Facet_base local_38 [4];
  int *local_34;
  int *local_30;
  int local_2c;
  char *local_28;
  int local_24;
  uint local_20;
  uint local_1c;
  int *local_18;
  undefined1 *local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_1004e045;
  local_10 = ExceptionList;
  uStack_5c = DAT_10069054 ^ (uint)&stack0xfffffffc;
  local_14 = (undefined1 *)&uStack_5c;
  ExceptionList = &local_10;
  iVar12 = 0;
  local_2c = 0;
  pcVar9 = param_2;
  do {
    cVar1 = *pcVar9;
    pcVar9 = pcVar9 + 1;
  } while (cVar1 != '\0');
  local_20 = (int)pcVar9 - (int)(param_2 + 1);
  local_24 = 0;
  iVar11 = *(int *)(*(int *)(*param_1 + 4) + 0x24 + (int)param_1);
  uVar10 = *(uint *)(*(int *)(*param_1 + 4) + 0x20 + (int)param_1);
  if ((iVar11 < 0) ||
     ((((iVar11 < 1 && (uVar10 == 0)) || (iVar11 < 0)) || ((iVar11 < 1 && (uVar10 <= local_20))))))
  {
    local_44 = 0;
    local_44._4_4_ = 0;
    local_44._0_4_ = (int *)0x0;
    iVar11 = local_44._4_4_;
    iVar13 = (int)(int *)local_44;
  }
  else {
    iVar11 = iVar11 - (uint)(uVar10 < local_20);
    iVar13 = uVar10 - local_20;
  }
  local_28 = param_2;
  local_18 = param_1;
  FUN_10007150(&local_44,param_1);
  piVar8 = local_18;
  local_8 = 0;
  if (local_44._4_1_ == '\0') {
    uVar10 = 4;
    this = (void *)(*(int *)(*local_18 + 4) + (int)local_18);
    if (*(int *)((int)this + 0x38) != 0) {
      uVar10 = 0;
    }
    FUN_10002bd0(this,uVar10 | *(uint *)(*(int *)(*local_18 + 4) + 0xc + (int)local_18) | 4,'\0');
    local_8 = 4;
    bVar5 = ___uncaught_exception();
    if (!bVar5) {
      FUN_10007e90((int *)local_44);
    }
    local_8 = CONCAT31(local_8._1_3_,5);
    piVar4 = *(int **)(*(int *)(*(int *)local_44 + 4) + 0x38 + (int)(int *)local_44);
    if (piVar4 != (int *)0x0) {
      (**(code **)(*piVar4 + 8))();
    }
    ExceptionList = local_10;
    return piVar8;
  }
  local_34 = *(int **)(*(int *)(*(int *)(*local_18 + 4) + 0x30 + (int)local_18) + 4);
  (**(code **)(*local_34 + 4))();
  local_8._0_1_ = 2;
  local_30 = (int *)FUN_10006410(local_38);
  local_8 = CONCAT31(local_8._1_3_,1);
  if ((local_34 != (int *)0x0) &&
     (puVar7 = (undefined4 *)(**(code **)(*local_34 + 8))(), puVar7 != (undefined4 *)0x0)) {
    (**(code **)*puVar7)(1);
  }
  if ((*(uint *)(*(int *)(*local_18 + 4) + 0x14 + (int)local_18) & 0x1c0) != 0x40) {
    do {
      if ((iVar11 < 0) || ((iVar11 < 1 && (iVar13 == 0)))) break;
      piVar8 = *(int **)(*(int *)(*local_18 + 4) + 0x38 + (int)local_18);
      uVar6 = *(ushort *)(*(int *)(*local_18 + 4) + 0x40 + (int)local_18);
      local_1c = (uint)uVar6;
      if (*(int *)piVar8[8] == 0) {
LAB_100080d1:
        uVar6 = (**(code **)(*piVar8 + 0xc))(local_1c);
      }
      else {
        iVar2 = *(int *)piVar8[0xc];
        if (iVar2 < 1) goto LAB_100080d1;
        *(int *)piVar8[0xc] = iVar2 + -1;
        puVar3 = *(ushort **)piVar8[8];
        *(ushort **)piVar8[8] = puVar3 + 1;
        *puVar3 = uVar6;
      }
      if (uVar6 == 0xffff) {
        iVar12 = 4;
        local_2c = 4;
        break;
      }
      bVar5 = iVar13 != 0;
      iVar13 = iVar13 + -1;
      iVar11 = iVar11 + -1 + (uint)bVar5;
    } while( true );
  }
LAB_100080f4:
  if (iVar12 == 0) {
    if ((local_24 < 0) || ((local_24 < 1 && (local_20 == 0)))) goto LAB_100081a5;
    piVar8 = *(int **)(*(int *)(*local_18 + 4) + 0x38 + (int)local_18);
    local_1c = CONCAT31(local_1c._1_3_,*local_28);
    uVar6 = (**(code **)(*local_30 + 0x30))(local_1c);
    local_34 = (int *)(uint)uVar6;
    if (*(int *)piVar8[8] == 0) {
LAB_10008168:
      uVar6 = (**(code **)(*piVar8 + 0xc))(local_34);
    }
    else {
      iVar12 = *(int *)piVar8[0xc];
      if (iVar12 < 1) goto LAB_10008168;
      *(int *)piVar8[0xc] = iVar12 + -1;
      puVar3 = *(ushort **)piVar8[8];
      *(ushort **)piVar8[8] = puVar3 + 1;
      *puVar3 = uVar6;
    }
    iVar12 = 4;
    bVar5 = local_20 != 0;
    local_20 = local_20 - 1;
    local_24 = local_24 + -1 + (uint)bVar5;
    local_28 = local_28 + 1;
    local_2c = iVar12;
    if (uVar6 != 0xffff) {
      iVar12 = 0;
      local_2c = iVar12;
    }
    goto LAB_100080f4;
  }
LAB_100081ff:
  iVar12 = *(int *)(*local_18 + 4);
  *(undefined4 *)(iVar12 + 0x20 + (int)local_18) = 0;
  *(undefined4 *)(iVar12 + 0x24 + (int)local_18) = 0;
  piVar8 = (int *)FUN_10008243();
  return piVar8;
LAB_100081a5:
  if ((iVar11 < 0) || ((iVar11 < 1 && (iVar13 == 0)))) goto LAB_100081ff;
  piVar8 = *(int **)(*(int *)(*local_18 + 4) + 0x38 + (int)local_18);
  uVar6 = *(ushort *)(*(int *)(*local_18 + 4) + 0x40 + (int)local_18);
  local_30 = (int *)(uint)uVar6;
  if ((*(int *)piVar8[8] == 0) || (*(int *)piVar8[0xc] < 1)) {
    uVar6 = (**(code **)(*piVar8 + 0xc))(local_30);
  }
  else {
    *(int *)piVar8[0xc] = *(int *)piVar8[0xc] + -1;
    puVar3 = *(ushort **)piVar8[8];
    *(ushort **)piVar8[8] = puVar3 + 1;
    *puVar3 = uVar6;
  }
  if (uVar6 == 0xffff) goto LAB_100081ff;
  bVar5 = iVar13 != 0;
  iVar13 = iVar13 + -1;
  iVar11 = iVar11 + -1 + (uint)bVar5;
  goto LAB_100081a5;
}


// FUNCTION_END

// FUNCTION_START: Catch_All@10008224 @ 10008224