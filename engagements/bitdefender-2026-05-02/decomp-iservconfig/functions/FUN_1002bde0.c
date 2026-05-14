void __thiscall FUN_1002bde0(void *this,int *param_1)

{
  int *piVar1;
  int *piVar2;
  code *pcVar3;
  int iVar4;
  int *piVar5;
  undefined4 local_1c;
  int *local_18;
  uint local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_10050cc0;
  local_10 = ExceptionList;
  local_14 = DAT_10069054 ^ (uint)&stack0xfffffffc;
  ExceptionList = &local_10;
                    /* WARNING: Load size is inaccurate */
  piVar1 = *this;
  local_1c = 0;
  if (piVar1 == (int *)0x0) {
    FUN_1002f620(0x80004003);
    pcVar3 = (code *)swi(3);
    (*pcVar3)();
    return;
  }
  local_8 = 0xffffffff;
  local_18 = (int *)0x0;
  iVar4 = (**(code **)(*piVar1 + 0x10))(piVar1,0xffffffff,1,&local_18,&local_1c,local_14);
  piVar1 = local_18;
  if (iVar4 == 0) {
    local_8 = 1;
    if (local_18 != (int *)0x0) {
      (**(code **)(*local_18 + 4))(local_18);
    }
    local_8 = 2;
    piVar2 = *(int **)((int)this + 4);
    piVar5 = piVar1;
    if (piVar2 != piVar1) {
      piVar5 = (int *)0x0;
      *(int **)((int)this + 4) = piVar1;
      if (piVar2 != (int *)0x0) {
        (**(code **)(*piVar2 + 8))(piVar2);
      }
    }
    local_8 = 3;
    if (piVar5 != (int *)0x0) {
      (**(code **)(*piVar5 + 8))(piVar5);
    }
    *param_1 = 0;
    param_1[1] = (int)&PTR_vftable_10069aa8;
  }
  else if (iVar4 == 1) {
    local_8 = 4;
                    /* WARNING: Load size is inaccurate */
    piVar1 = *this;
    if (piVar1 != (int *)0x0) {
      *(undefined4 *)this = 0;
      (**(code **)(*piVar1 + 8))(piVar1);
    }
    local_8 = 5;
    piVar1 = *(int **)((int)this + 4);
    if (piVar1 != (int *)0x0) {
      *(undefined4 *)((int)this + 4) = 0;
      (**(code **)(*piVar1 + 8))(piVar1);
    }
    *param_1 = 0;
    param_1[1] = (int)&PTR_vftable_10069aa8;
  }
  else {
    *param_1 = iVar4;
    param_1[1] = (int)&PTR_vftable_10069ab8;
  }
  local_8 = 8;
  if (local_18 != (int *)0x0) {
    (**(code **)(*local_18 + 8))(local_18);
  }
  ExceptionList = local_10;
  FUN_1002e315(local_14 ^ (uint)&stack0xfffffffc);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_1002bf50 @ 1002bf50