void __thiscall FUN_100230a0(void *this,undefined1 param_1)

{
  uint uVar1;
  undefined4 *this_00;
  uint local_8;
  
  this_00 = *(undefined4 **)((int)this + 4);
  uVar1 = this_00[4];
  if (uVar1 < (uint)this_00[5]) {
    this_00[4] = uVar1 + 1;
    if (0xf < (uint)this_00[5]) {
      this_00 = (undefined4 *)*this_00;
    }
    *(undefined1 *)((int)this_00 + uVar1) = param_1;
    *(undefined1 *)((int)this_00 + uVar1 + 1) = 0;
    return;
  }
  local_8 = (uint)this & 0xffffff00;
  FUN_10014ac0(this_00,this_00,local_8,param_1);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_100230f0 @ 100230f0