void __thiscall FUN_10005ca0(void *this,undefined4 param_1)

{
  undefined2 uVar1;
  uint uVar2;
  int *piVar3;
  undefined4 *puVar4;
  _Facet_base local_18 [4];
  int *local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_1004ddbd;
  local_10 = ExceptionList;
  uVar2 = DAT_10069054 ^ (uint)&stack0xfffffffc;
  ExceptionList = &local_10;
  FUN_10002c40(this);
  *(undefined4 *)((int)this + 0x38) = param_1;
  *(undefined4 *)((int)this + 0x3c) = 0;
  local_14 = *(int **)(*(int *)((int)this + 0x30) + 4);
  (**(code **)(*local_14 + 4))(uVar2);
  local_8 = 0;
  piVar3 = (int *)FUN_10006410(local_18);
  uVar1 = (**(code **)(*piVar3 + 0x30))(0x20);
  local_8 = 0xffffffff;
  if (local_14 != (int *)0x0) {
    puVar4 = (undefined4 *)(**(code **)(*local_14 + 8))();
    if (puVar4 != (undefined4 *)0x0) {
      (**(code **)*puVar4)(1);
    }
  }
  *(undefined2 *)((int)this + 0x40) = uVar1;
  if (*(int *)((int)this + 0x38) == 0) {
    FUN_10002bd0(this,*(uint *)((int)this + 0xc) | 4,'\0');
  }
  ExceptionList = local_10;
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_10005d60 @ 10005d60