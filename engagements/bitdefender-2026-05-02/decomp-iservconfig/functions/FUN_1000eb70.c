uint * __thiscall FUN_1000eb70(void *this,uint *param_1)

{
  uint uVar1;
  uint uVar2;
  uint uVar3;
  uint *puVar4;
  uint uVar5;
  
  *(undefined4 *)this = 0;
  *(undefined4 *)((int)this + 0x10) = 0;
  *(undefined4 *)((int)this + 0x14) = 0;
  uVar1 = param_1[4];
  if (7 < param_1[5]) {
    param_1 = (uint *)*param_1;
  }
  if (uVar1 < 8) {
    uVar5 = param_1[1];
    uVar2 = param_1[2];
    uVar3 = param_1[3];
    *(uint *)this = *param_1;
    *(uint *)((int)this + 4) = uVar5;
    *(uint *)((int)this + 8) = uVar2;
    *(uint *)((int)this + 0xc) = uVar3;
    *(uint *)((int)this + 0x10) = uVar1;
    *(undefined4 *)((int)this + 0x14) = 7;
    return (uint *)this;
  }
  uVar5 = uVar1 | 7;
  if (0x7ffffffe < uVar5) {
    uVar5 = 0x7ffffffe;
  }
  puVar4 = (uint *)FUN_10001e50(-(uint)(0xfffffffe < uVar5) | uVar5 + 1);
  *(uint **)this = puVar4;
  FUN_100301d0(puVar4,param_1,uVar1 * 2 + 2);
  *(uint *)((int)this + 0x10) = uVar1;
  *(uint *)((int)this + 0x14) = uVar5;
  return (uint *)this;
}


// FUNCTION_END

// FUNCTION_START: FUN_1000ec10 @ 1000ec10