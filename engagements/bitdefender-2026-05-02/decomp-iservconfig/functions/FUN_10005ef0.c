void __thiscall FUN_10005ef0(void *this,uint param_1,char param_2)

{
  uint uVar1;
  
  uVar1 = 4;
  if (*(int *)((int)this + 0x38) != 0) {
    uVar1 = 0;
  }
  FUN_10002bd0(this,uVar1 | *(uint *)((int)this + 0xc) | param_1,param_2);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_10005f20 @ 10005f20