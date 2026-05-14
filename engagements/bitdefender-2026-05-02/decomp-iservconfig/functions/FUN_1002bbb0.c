int * __fastcall FUN_1002bbb0(int *param_1,undefined4 param_2,uint param_3)

{
  ushort *puVar1;
  bool bVar2;
  ushort uVar3;
  int *piVar4;
  uint uVar5;
  int iVar6;
  void *this;
  int iVar7;
  undefined8 uVar8;
  uint uStack_48;
  int *local_34;
  char local_30;
  int *local_28;
  undefined4 local_24;
  undefined4 local_20;
  uint local_1c;
  undefined1 *local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_10050c9d;
  local_10 = ExceptionList;
  uStack_48 = DAT_10069054 ^ (uint)&stack0xfffffffc;
  local_14 = (undefined1 *)&uStack_48;
  ExceptionList = &local_10;
  local_24 = 0;
  uVar5 = *(uint *)(*(int *)(*param_1 + 4) + 0x20 + (int)param_1);
  iVar7 = *(int *)(*(int *)(*param_1 + 4) + 0x24 + (int)param_1);
  if ((iVar7 < 0) || (((iVar7 < 1 && (uVar5 == 0)) || (uVar5 <= param_3)))) {
    iVar7 = 0;
  }
  else {
    iVar7 = uVar5 - param_3;
  }
  local_28 = param_1;
  local_20 = param_2;
  FUN_10007150(&local_34,param_1);
  local_8 = 0;
  if (local_30 == '\0') {
    uVar5 = 4;
    this = (void *)(*(int *)(*param_1 + 4) + (int)param_1);
    if (*(int *)((int)this + 0x38) != 0) {
      uVar5 = 0;
    }
    FUN_10002bd0(this,uVar5 | *(uint *)((int)this + 0xc) | 4,'\0');
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
    for (; iVar7 != 0; iVar7 = iVar7 + -1) {
      piVar4 = *(int **)(*(int *)(*param_1 + 4) + 0x38 + (int)param_1);
      uVar3 = *(ushort *)(*(int *)(*param_1 + 4) + 0x40 + (int)param_1);
      local_1c = (uint)uVar3;
      if ((*(int *)piVar4[8] == 0) || (*(int *)piVar4[0xc] < 1)) {
        uVar3 = (**(code **)(*piVar4 + 0xc))(local_1c);
      }
      else {
        *(int *)piVar4[0xc] = *(int *)piVar4[0xc] + -1;
        puVar1 = *(ushort **)piVar4[8];
        *(ushort **)piVar4[8] = puVar1 + 1;
        *puVar1 = uVar3;
      }
      if (uVar3 == 0xffff) {
        local_24 = 4;
        goto LAB_1002bcc0;
      }
    }
    iVar6 = *param_1;
  }
  uVar8 = FUN_10008ac0(*(void **)(*(int *)(iVar6 + 4) + 0x38 + (int)param_1),local_20,param_3,0);
  if (((uint)uVar8 == param_3) && ((int)((ulonglong)uVar8 >> 0x20) == 0)) {
LAB_1002bcc0:
    do {
      if (iVar7 == 0) break;
      piVar4 = *(int **)(*(int *)(*param_1 + 4) + 0x38 + (int)param_1);
      uVar3 = *(ushort *)(*(int *)(*param_1 + 4) + 0x40 + (int)param_1);
      local_1c = (uint)uVar3;
      if ((*(int *)piVar4[8] == 0) || (*(int *)piVar4[0xc] < 1)) {
        uVar3 = (**(code **)(*piVar4 + 0xc))(local_1c);
      }
      else {
        *(int *)piVar4[0xc] = *(int *)piVar4[0xc] + -1;
        puVar1 = *(ushort **)piVar4[8];
        *(ushort **)piVar4[8] = puVar1 + 1;
        *puVar1 = uVar3;
      }
      if (uVar3 == 0xffff) break;
      iVar7 = iVar7 + -1;
    } while( true );
  }
  iVar7 = *(int *)(*param_1 + 4);
  *(undefined4 *)(iVar7 + 0x20 + (int)param_1) = 0;
  *(undefined4 *)(iVar7 + 0x24 + (int)param_1) = 0;
  piVar4 = (int *)FUN_1002bd54();
  return piVar4;
}


// FUNCTION_END

// FUNCTION_START: Catch_All@1002bd35 @ 1002bd35