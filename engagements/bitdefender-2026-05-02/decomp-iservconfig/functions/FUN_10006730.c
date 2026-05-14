int * __thiscall FUN_10006730(void *this,undefined4 param_1)

{
  int iVar1;
  int *piVar2;
  bool bVar3;
  undefined4 *puVar4;
  void *this_00;
  uint uVar5;
  uint uVar6;
  uint uStack_50;
  uint local_44;
  int *local_40;
  int *local_3c;
  char local_38;
  undefined4 local_34;
  void *local_30;
  int *local_2c;
  undefined1 *puStack_24;
  undefined1 *local_20;
  void *local_1c;
  undefined1 *puStack_18;
  undefined4 local_14;
  
  puStack_24 = &stack0xfffffffc;
  local_14 = 0xffffffff;
  puStack_18 = &LAB_1004de65;
  local_1c = ExceptionList;
  uStack_50 = DAT_10069054 ^ (uint)&stack0xfffffff0;
  local_20 = (undefined1 *)&uStack_50;
  ExceptionList = &local_1c;
  uVar6 = 0;
  local_34 = 0;
  local_30 = this;
  FUN_10007150(&local_3c,(int *)this);
  local_14 = 0;
  if (local_38 != '\0') {
                    /* WARNING: Load size is inaccurate */
    local_40 = *(int **)(*(int *)(*(int *)(*this + 4) + 0x30 + (int)this) + 4);
    (**(code **)(*local_40 + 4))();
    local_14 = CONCAT31(local_14._1_3_,1);
    local_2c = (int *)FUN_10008520((_Facet_base *)&local_44);
    if ((local_40 != (int *)0x0) &&
       (puVar4 = (undefined4 *)(**(code **)(*local_40 + 8))(), puVar4 != (undefined4 *)0x0)) {
      (**(code **)*puVar4)(1);
    }
                    /* WARNING: Load size is inaccurate */
    local_14 = CONCAT31(local_14._1_3_,2);
    iVar1 = *(int *)(*this + 4) + (int)this;
    local_44 = local_44 & 0xffffff00;
    (**(code **)(*local_2c + 0x24))
              (&local_44,local_44,*(undefined4 *)(iVar1 + 0x38),iVar1,*(undefined2 *)(iVar1 + 0x40),
               param_1);
    if (local_44._0_1_ != (_Facet_base)0x0) {
      uVar6 = 4;
    }
  }
  local_14 = 0;
  uVar5 = 4;
                    /* WARNING: Load size is inaccurate */
  this_00 = (void *)(*(int *)(*this + 4) + (int)this);
  if (*(int *)((int)this_00 + 0x38) != 0) {
    uVar5 = 0;
  }
  FUN_10002bd0(this_00,uVar5 | *(uint *)(*(int *)(*this + 4) + 0xc + (int)this) | uVar6,'\0');
  local_14 = 4;
  bVar3 = ___uncaught_exception();
  if (!bVar3) {
    FUN_10007e90(local_3c);
  }
  local_14 = CONCAT31(local_14._1_3_,5);
  piVar2 = *(int **)(*(int *)(*local_3c + 4) + 0x38 + (int)local_3c);
  if (piVar2 != (int *)0x0) {
    (**(code **)(*piVar2 + 8))();
  }
  ExceptionList = local_1c;
  return (int *)this;
}


// FUNCTION_END

// FUNCTION_START: Catch_All@10006815 @ 10006815