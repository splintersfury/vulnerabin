ulonglong __thiscall FUN_10023040(void *this,uint *param_1,uint param_2)

{
  int iVar1;
  uint uVar2;
  uint *puVar3;
  undefined4 *this_00;
  undefined4 extraout_EDX;
  ulonglong uVar4;
  
  uVar2 = param_2;
  this_00 = *(undefined4 **)((int)this + 4);
  iVar1 = this_00[4];
  if (param_2 <= (uint)(this_00[5] - iVar1)) {
    this_00[4] = iVar1 + param_2;
    if (0xf < (uint)this_00[5]) {
      this_00 = (undefined4 *)*this_00;
    }
    uVar4 = FUN_100301d0((uint *)((int)this_00 + iVar1),param_1,param_2);
    *(undefined1 *)((int)this_00 + iVar1 + param_2) = 0;
    return uVar4;
  }
  param_2 = param_2 & 0xffffff00;
  puVar3 = FUN_100062b0(this_00,uVar2,param_2,param_1,uVar2);
  return CONCAT44(extraout_EDX,puVar3);
}


// FUNCTION_END

// FUNCTION_START: FUN_100230a0 @ 100230a0