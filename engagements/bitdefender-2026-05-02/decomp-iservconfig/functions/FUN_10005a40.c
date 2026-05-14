undefined4 * __thiscall FUN_10005a40(void *this,undefined4 *param_1)

{
  uint uVar1;
  uint *local_20;
  uint uStack_1c;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  puStack_c = &LAB_1004dd8e;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  *param_1 = 0;
  param_1[4] = 0;
  param_1[5] = 7;
  *(undefined2 *)param_1 = 0;
  local_8 = 0;
  if ((((byte)*(uint *)((int)this + 0x3c) & 0x22) == 2) ||
     (uVar1 = **(uint **)((int)this + 0x20), uVar1 == 0)) {
    if (((*(uint *)((int)this + 0x3c) & 4) == 0) && (**(int **)((int)this + 0x1c) != 0)) {
      local_20 = (uint *)**(int **)((int)this + 0xc);
      uStack_1c = (**(int **)((int)this + 0x2c) * 2 - (int)local_20) + **(int **)((int)this + 0x1c)
                  >> 1;
    }
    else {
      uStack_1c = 0;
      local_20 = (uint *)0x0;
    }
  }
  else {
    if (uVar1 < *(uint *)((int)this + 0x38)) {
      uVar1 = *(uint *)((int)this + 0x38);
    }
    local_20 = (uint *)**(int **)((int)this + 0x10);
    uStack_1c = (int)(uVar1 - (int)local_20) >> 1;
  }
  if (local_20 != (uint *)0x0) {
    FUN_10001d40(param_1,local_20,uStack_1c);
  }
  ExceptionList = local_10;
  return param_1;
}


// FUNCTION_END

// FUNCTION_START: FUN_10005b20 @ 10005b20