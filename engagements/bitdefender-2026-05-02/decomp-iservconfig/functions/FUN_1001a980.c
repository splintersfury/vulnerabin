int * __thiscall FUN_1001a980(void *this,undefined4 param_1)

{
  int *piVar1;
  bool bVar2;
  void *pvVar3;
  undefined4 *puVar4;
  char *pcVar5;
  int iVar6;
  uint uVar7;
  uint uVar8;
  uint uStack_3c;
  uint local_2c;
  int *local_28;
  int *local_24;
  char local_20;
  undefined4 local_1c;
  void *local_18;
  undefined1 *local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_1004f6a5;
  local_10 = ExceptionList;
  uStack_3c = DAT_10069054 ^ (uint)&stack0xfffffffc;
  local_14 = (undefined1 *)&uStack_3c;
  ExceptionList = &local_10;
  uVar8 = 0;
  local_1c = 0;
  local_18 = this;
  FUN_10007150(&local_24,(int *)this);
  local_8 = 0;
  if (local_20 != '\0') {
                    /* WARNING: Load size is inaccurate */
    local_28 = *(int **)(*(int *)(*(int *)(*this + 4) + 0x30 + (int)this) + 4);
    (**(code **)(*local_28 + 4))();
    local_8 = CONCAT31(local_8._1_3_,1);
    pvVar3 = (void *)FUN_10008520((_Facet_base *)&local_2c);
    if ((local_28 != (int *)0x0) &&
       (puVar4 = (undefined4 *)(**(code **)(*local_28 + 8))(), puVar4 != (undefined4 *)0x0)) {
      (**(code **)*puVar4)(1);
    }
    local_8 = CONCAT31(local_8._1_3_,2);
                    /* WARNING: Load size is inaccurate */
    iVar6 = *(int *)(*this + 4) + (int)this;
    local_2c = local_2c & 0xffffff00;
    pcVar5 = (char *)FUN_1001ab10(pvVar3,&local_2c,iVar6,(uint)*(ushort *)(iVar6 + 0x40),param_1,
                                  local_2c,*(undefined4 *)(iVar6 + 0x38));
    uVar8 = 4;
    if (*pcVar5 == '\0') {
      uVar8 = 0;
    }
  }
  local_8 = 0;
  uVar7 = 4;
                    /* WARNING: Load size is inaccurate */
  pvVar3 = (void *)(*(int *)(*this + 4) + (int)this);
  if (*(int *)((int)pvVar3 + 0x38) != 0) {
    uVar7 = 0;
  }
  FUN_10002bd0(pvVar3,uVar7 | *(uint *)(*(int *)(*this + 4) + 0xc + (int)this) | uVar8,'\0');
  local_8 = 4;
  bVar2 = ___uncaught_exception();
  if (!bVar2) {
    FUN_10007e90(local_24);
  }
  local_8 = CONCAT31(local_8._1_3_,5);
  piVar1 = *(int **)(*(int *)(*local_24 + 4) + 0x38 + (int)local_24);
  if (piVar1 != (int *)0x0) {
    (**(code **)(*piVar1 + 8))();
  }
  ExceptionList = local_10;
  return (int *)this;
}


// FUNCTION_END

// FUNCTION_START: Catch_All@1001aa49 @ 1001aa49