uint * __thiscall FUN_10005610(void *this,uint *param_1)

{
  uint uVar1;
  int iVar2;
  uint *puVar3;
  
  uVar1 = param_1[4];
  puVar3 = param_1;
  if (0xf < param_1[5]) {
    puVar3 = (uint *)*param_1;
  }
  iVar2 = *(int *)((int)this + 0x10);
  if (uVar1 <= *(uint *)((int)this + 0x14) - iVar2) {
    *(uint *)((int)this + 0x10) = uVar1 + iVar2;
    param_1 = (uint *)this;
    if (0xf < *(uint *)((int)this + 0x14)) {
                    /* WARNING: Load size is inaccurate */
      param_1 = *this;
    }
    FUN_100301d0((uint *)((int)param_1 + iVar2),puVar3,uVar1);
    *(undefined1 *)((int)param_1 + iVar2 + uVar1) = 0;
    return (uint *)this;
  }
  param_1 = (uint *)((uint)param_1 & 0xffffff00);
  puVar3 = FUN_100062b0(this,uVar1,param_1,puVar3,uVar1);
  return puVar3;
}


// FUNCTION_END

// FUNCTION_START: FUN_10005690 @ 10005690