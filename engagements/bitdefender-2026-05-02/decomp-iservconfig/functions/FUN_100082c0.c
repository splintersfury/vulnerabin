int * __fastcall FUN_100082c0(int *param_1,short *param_2)

{
  ushort *puVar1;
  bool bVar2;
  short sVar3;
  ushort uVar4;
  int *piVar5;
  uint uVar6;
  short *psVar7;
  int iVar8;
  void *this;
  int iVar9;
  int iVar10;
  undefined8 uVar11;
  uint uStack_44;
  undefined8 local_24;
  short *local_1c;
  uint local_18;
  undefined1 *local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_1004e07d;
  local_10 = ExceptionList;
  uStack_44 = DAT_10069054 ^ (uint)&stack0xfffffffc;
  local_14 = (undefined1 *)&uStack_44;
  ExceptionList = &local_10;
  psVar7 = param_2;
  do {
    sVar3 = *psVar7;
    psVar7 = psVar7 + 1;
  } while (sVar3 != 0);
  local_18 = (int)psVar7 - (int)(param_2 + 1) >> 1;
  iVar10 = *(int *)(*(int *)(*param_1 + 4) + 0x24 + (int)param_1);
  uVar6 = *(uint *)(*(int *)(*param_1 + 4) + 0x20 + (int)param_1);
  if ((iVar10 < 0) ||
     ((iVar10 < 1 && (((uVar6 == 0 || (iVar10 < 0)) || ((iVar10 < 1 && (uVar6 <= local_18)))))))) {
    local_24 = 0;
    local_24._4_4_ = 0;
    local_24._0_4_ = (int *)0x0;
    iVar9 = (int)(int *)local_24;
    iVar10 = local_24._4_4_;
  }
  else {
    iVar9 = uVar6 - local_18;
    iVar10 = iVar10 - (uint)(uVar6 < local_18);
  }
  local_1c = param_2;
  FUN_10007150(&local_24,param_1);
  local_8 = 0;
  if (local_24._4_1_ == '\0') {
    uVar6 = 4;
    this = (void *)(*(int *)(*param_1 + 4) + (int)param_1);
    if (*(int *)((int)this + 0x38) != 0) {
      uVar6 = 0;
    }
    FUN_10002bd0(this,uVar6 | *(uint *)((int)this + 0xc) | 4,'\0');
    local_8 = 3;
    bVar2 = ___uncaught_exception();
    if (!bVar2) {
      FUN_10007e90((int *)local_24);
    }
    local_8 = CONCAT31(local_8._1_3_,4);
    piVar5 = *(int **)(*(int *)(*(int *)local_24 + 4) + 0x38 + (int)(int *)local_24);
    if (piVar5 != (int *)0x0) {
      (**(code **)(*piVar5 + 8))();
    }
    ExceptionList = local_10;
    return param_1;
  }
  local_8 = 1;
  iVar8 = *param_1;
  if ((*(uint *)(*(int *)(iVar8 + 4) + 0x14 + (int)param_1) & 0x1c0) != 0x40) {
    for (; (-1 < iVar10 && ((0 < iVar10 || (iVar9 != 0)))); iVar9 = iVar9 + -1) {
      piVar5 = *(int **)(*(int *)(*param_1 + 4) + 0x38 + (int)param_1);
      sVar3 = *(short *)(*(int *)(*param_1 + 4) + 0x40 + (int)param_1);
      if (*(int *)piVar5[8] == 0) {
LAB_100083c1:
        sVar3 = (**(code **)(*piVar5 + 0xc))(sVar3);
      }
      else {
        iVar8 = *(int *)piVar5[0xc];
        if (iVar8 < 1) goto LAB_100083c1;
        *(int *)piVar5[0xc] = iVar8 + -1;
        psVar7 = *(short **)piVar5[8];
        *(short **)piVar5[8] = psVar7 + 1;
        *psVar7 = sVar3;
      }
      if (sVar3 == -1) goto LAB_1000846f;
      iVar10 = iVar10 + -1 + (uint)(iVar9 != 0);
    }
    iVar8 = *param_1;
  }
  uVar11 = FUN_10008ac0(*(void **)(*(int *)(iVar8 + 4) + 0x38 + (int)param_1),local_1c,local_18,0);
  if (((uint)uVar11 == local_18) && ((int)((ulonglong)uVar11 >> 0x20) == 0)) {
    for (; (-1 < iVar10 && ((0 < iVar10 || (iVar9 != 0)))); iVar9 = iVar9 + -1) {
      piVar5 = *(int **)(*(int *)(*param_1 + 4) + 0x38 + (int)param_1);
      uVar4 = *(ushort *)(*(int *)(*param_1 + 4) + 0x40 + (int)param_1);
      local_18 = (uint)uVar4;
      if ((*(int *)piVar5[8] == 0) || (*(int *)piVar5[0xc] < 1)) {
        uVar4 = (**(code **)(*piVar5 + 0xc))(local_18);
      }
      else {
        *(int *)piVar5[0xc] = *(int *)piVar5[0xc] + -1;
        puVar1 = *(ushort **)piVar5[8];
        *(ushort **)piVar5[8] = puVar1 + 1;
        *puVar1 = uVar4;
      }
      if (uVar4 == 0xffff) break;
      iVar10 = iVar10 + -1 + (uint)(iVar9 != 0);
    }
  }
LAB_1000846f:
  iVar10 = *(int *)(*param_1 + 4);
  *(undefined4 *)(iVar10 + 0x20 + (int)param_1) = 0;
  *(undefined4 *)(iVar10 + 0x24 + (int)param_1) = 0;
  piVar5 = (int *)FUN_100084a5();
  return piVar5;
}


// FUNCTION_END

// FUNCTION_START: Catch_All@10008486 @ 10008486