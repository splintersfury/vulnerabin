undefined4 * __thiscall FUN_10007150(void *this,int *param_1)

{
  int *piVar1;
  int *piVar2;
  bool bVar3;
  uint uVar4;
  int iVar5;
  int *local_1c;
  char local_18;
  void *local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_1004df25;
  local_10 = ExceptionList;
  uVar4 = DAT_10069054 ^ (uint)&stack0xfffffffc;
  ExceptionList = &local_10;
  *(int **)this = param_1;
  iVar5 = *param_1;
  piVar1 = *(int **)(*(int *)(iVar5 + 4) + 0x38 + (int)param_1);
  local_14 = this;
  if (piVar1 != (int *)0x0) {
    (**(code **)(*piVar1 + 4))(uVar4);
    iVar5 = *param_1;
  }
  local_8 = 0;
  if (*(int *)(*(int *)(iVar5 + 4) + 0xc + (int)param_1) == 0) {
    piVar1 = *(int **)((int)param_1 + *(int *)(iVar5 + 4) + 0x3c);
    if ((piVar1 == (int *)0x0) || (piVar1 == param_1)) {
      bVar3 = true;
    }
    else {
      piVar2 = *(int **)(*(int *)(*piVar1 + 4) + 0x38 + (int)piVar1);
      if (piVar2 != (int *)0x0) {
        FUN_10007150(&local_1c,piVar1);
        local_8._0_1_ = 1;
        if (local_18 != '\0') {
          iVar5 = (**(code **)(*piVar2 + 0x34))();
          if (iVar5 == -1) {
            FUN_10002bd0((void *)(*(int *)(*piVar1 + 4) + (int)piVar1),
                         *(uint *)(*(int *)(*piVar1 + 4) + 0xc + (int)piVar1) | 4,'\0');
          }
        }
        local_8 = CONCAT31(local_8._1_3_,2);
        bVar3 = ___uncaught_exception();
        if (!bVar3) {
          FUN_10007e90(local_1c);
        }
        local_8 = CONCAT31(local_8._1_3_,3);
        piVar1 = *(int **)(*(int *)(*local_1c + 4) + 0x38 + (int)local_1c);
        if (piVar1 != (int *)0x0) {
          (**(code **)(*piVar1 + 8))();
        }
        iVar5 = *param_1;
      }
      bVar3 = *(int *)(*(int *)(iVar5 + 4) + 0xc + (int)param_1) == 0;
    }
  }
  else {
    bVar3 = false;
  }
  *(bool *)((int)this + 4) = bVar3;
  ExceptionList = local_10;
  return (undefined4 *)this;
}


// FUNCTION_END

// FUNCTION_START: FUN_10007270 @ 10007270