int __thiscall FUN_100110c0(void *this,undefined4 *param_1,undefined1 param_2)

{
  char cVar1;
  uint uVar2;
  undefined4 uVar3;
  lconv *plVar4;
  int *in_stack_00000030;
  void *local_10;
  undefined1 *puStack_c;
  undefined1 local_8;
  undefined3 uStack_7;
  
  puStack_c = &LAB_1004ec08;
  local_10 = ExceptionList;
  uVar2 = DAT_10069054 ^ (uint)&stack0xfffffffc;
  ExceptionList = &local_10;
  *(undefined4 *)((int)this + 0x24) = 0;
  local_8 = 1;
  uStack_7 = 0;
  if (in_stack_00000030 != (int *)0x0) {
    uVar3 = (**(code **)*in_stack_00000030)(this,uVar2);
    *(undefined4 *)((int)this + 0x24) = uVar3;
  }
  *(undefined4 *)((int)this + 0x28) = 0;
  *(undefined4 *)((int)this + 0x30) = 0;
  *(undefined4 *)((int)this + 0x34) = 0;
  *(undefined4 *)((int)this + 0x30) = *param_1;
  *(undefined4 *)((int)this + 0x34) = param_1[1];
  *param_1 = 0;
  param_1[1] = 0;
  *(undefined4 *)((int)this + 0x38) = 0xffffffff;
  *(undefined1 *)((int)this + 0x3c) = 0;
  *(undefined4 *)((int)this + 0x40) = 0;
  *(undefined4 *)((int)this + 0x44) = 0;
  *(undefined4 *)((int)this + 0x48) = 0;
  *(undefined4 *)((int)this + 0x4c) = 0;
  *(undefined4 *)((int)this + 0x50) = 0;
  *(undefined4 *)((int)this + 0x54) = 0;
  *(undefined4 *)((int)this + 0x58) = 0;
  *(undefined4 *)((int)this + 0x68) = 0;
  *(undefined4 *)((int)this + 0x6c) = 0xf;
  *(undefined1 **)((int)this + 0x70) = &DAT_1005e237;
  *(undefined4 *)((int)this + 0x78) = 0;
  *(undefined4 *)((int)this + 0x7c) = 0;
  *(undefined4 *)((int)this + 0x80) = 0;
  *(undefined4 *)((int)this + 0x84) = 0;
  *(undefined8 *)((int)this + 0x88) = 0;
  plVar4 = _localeconv();
  if (plVar4->decimal_point == (char *)0x0) {
    cVar1 = '.';
  }
  else {
    cVar1 = *plVar4->decimal_point;
  }
  *(char *)((int)this + 0x90) = cVar1;
  _local_8 = CONCAT31(uStack_7,3);
  *(undefined1 *)((int)this + 0x98) = param_2;
  uVar3 = FUN_10012320((undefined4 *)((int)this + 0x30));
  *(undefined4 *)((int)this + 0x28) = uVar3;
  if (in_stack_00000030 != (int *)0x0) {
    (**(code **)(*in_stack_00000030 + 0x10))(in_stack_00000030 != (int *)&stack0x0000000c);
  }
  ExceptionList = local_10;
  return (int)this;
}


// FUNCTION_END

// FUNCTION_START: FUN_10011220 @ 10011220