void __thiscall FUN_10013b40(void *this,undefined1 param_1)

{
  uint uVar1;
  undefined4 *this_00;
  uint local_c;
  
  uVar1 = *(uint *)((int)this + 0x38);
  this_00 = (undefined4 *)((int)this + 0x28);
  if (uVar1 < *(uint *)((int)this + 0x3c)) {
    *(uint *)((int)this + 0x38) = uVar1 + 1;
    if (0xf < *(uint *)((int)this + 0x3c)) {
      this_00 = (undefined4 *)*this_00;
    }
    *(undefined1 *)((int)this_00 + uVar1) = param_1;
    *(undefined1 *)((int)this_00 + uVar1 + 1) = 0;
    return;
  }
  local_c = local_c & 0xffffff00;
  FUN_10014ac0(this_00,this_00,local_c,param_1);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_10013b90 @ 10013b90