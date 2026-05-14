int * __thiscall FUN_10027670(void *this,undefined4 param_1)

{
  int *piVar1;
  bool bVar2;
  void *pvVar3;
  undefined4 *puVar4;
  char *pcVar5;
  int iVar6;
  uint uVar7;
  uint uVar8;
  uint uStack_50;
  uint local_40;
  int *local_3c;
  int *local_38;
  char local_34;
  undefined4 local_30;
  void *local_2c;
  undefined1 *puStack_24;
  undefined1 *local_20;
  void *local_1c;
  undefined1 *puStack_18;
  undefined4 local_14;
  
  puStack_24 = &stack0xfffffffc;
  local_14 = 0xffffffff;
  puStack_18 = &LAB_10050385;
  local_1c = ExceptionList;
  uStack_50 = DAT_10069054 ^ (uint)&stack0xfffffff0;
  local_20 = (undefined1 *)&uStack_50;
  ExceptionList = &local_1c;
  uVar8 = 0;
  local_30 = 0;
  local_2c = this;
  FUN_10007150(&local_38,(int *)this);
  local_14 = 0;
  if (local_34 != '\0') {
                    /* WARNING: Load size is inaccurate */
    local_3c = *(int **)(*(int *)(*(int *)(*this + 4) + 0x30 + (int)this) + 4);
    (**(code **)(*local_3c + 4))();
    local_14 = CONCAT31(local_14._1_3_,1);
    pvVar3 = (void *)FUN_10008520((_Facet_base *)&local_40);
    if ((local_3c != (int *)0x0) &&
       (puVar4 = (undefined4 *)(**(code **)(*local_3c + 8))(), puVar4 != (undefined4 *)0x0)) {
      (**(code **)*puVar4)(1);
    }
    local_14 = CONCAT31(local_14._1_3_,2);
                    /* WARNING: Load size is inaccurate */
    iVar6 = *(int *)(*this + 4) + (int)this;
    local_40 = local_40 & 0xffffff00;
    pcVar5 = (char *)FUN_1001ab10(pvVar3,&local_40,iVar6,(uint)*(ushort *)(iVar6 + 0x40),param_1,
                                  local_40,*(undefined4 *)(iVar6 + 0x38));
    uVar8 = 4;
    if (*pcVar5 == '\0') {
      uVar8 = 0;
    }
  }
  local_14 = 0;
  uVar7 = 4;
                    /* WARNING: Load size is inaccurate */
  pvVar3 = (void *)(*(int *)(*this + 4) + (int)this);
  if (*(int *)((int)pvVar3 + 0x38) != 0) {
    uVar7 = 0;
  }
  FUN_10002bd0(pvVar3,uVar7 | *(uint *)(*(int *)(*this + 4) + 0xc + (int)this) | uVar8,'\0');
  local_14 = 4;
  bVar2 = ___uncaught_exception();
  if (!bVar2) {
    FUN_10007e90(local_38);
  }
  local_14 = CONCAT31(local_14._1_3_,5);
  piVar1 = *(int **)(*(int *)(*local_38 + 4) + 0x38 + (int)local_38);
  if (piVar1 != (int *)0x0) {
    (**(code **)(*piVar1 + 8))();
  }
  ExceptionList = local_1c;
  return (int *)this;
}


// FUNCTION_END

// FUNCTION_START: Catch_All@1002774d @ 1002774d