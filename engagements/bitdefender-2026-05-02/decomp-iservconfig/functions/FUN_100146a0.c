undefined4 * __thiscall FUN_100146a0(void *this,undefined4 *param_1)

{
  undefined4 uVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  
  uVar1 = param_1[1];
  *(undefined4 *)this = *param_1;
  *(undefined4 *)((int)this + 4) = uVar1;
  *(undefined4 *)((int)this + 8) = 0;
  *(undefined4 *)((int)this + 0x18) = 0;
  *(undefined4 *)((int)this + 0x1c) = 0;
  uVar1 = param_1[3];
  uVar2 = param_1[4];
  uVar3 = param_1[5];
  *(undefined4 *)((int)this + 8) = param_1[2];
  *(undefined4 *)((int)this + 0xc) = uVar1;
  *(undefined4 *)((int)this + 0x10) = uVar2;
  *(undefined4 *)((int)this + 0x14) = uVar3;
  *(undefined8 *)((int)this + 0x18) = *(undefined8 *)(param_1 + 6);
  param_1[6] = 0;
  param_1[7] = 0xf;
  *(undefined1 *)(param_1 + 2) = 0;
  *(undefined1 *)((int)this + 0x20) = 1;
  return (undefined4 *)this;
}


// FUNCTION_END

// FUNCTION_START: FUN_10014700 @ 10014700