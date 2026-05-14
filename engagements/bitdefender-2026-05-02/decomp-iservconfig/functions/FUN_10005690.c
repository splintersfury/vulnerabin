undefined4 * __thiscall FUN_10005690(void *this,uint *param_1)

{
  uint uVar1;
  uint *puVar2;
  
  *(undefined4 *)this = 0;
  *(undefined4 *)((int)this + 0x10) = 0;
  *(undefined4 *)((int)this + 0x14) = 0xf;
  puVar2 = param_1;
  do {
    uVar1 = *puVar2;
    puVar2 = (uint *)((int)puVar2 + 1);
  } while ((char)uVar1 != '\0');
  FUN_10008e70(this,param_1,(int)puVar2 - ((int)param_1 + 1));
  return (undefined4 *)this;
}


// FUNCTION_END

// FUNCTION_START: FUN_100056d0 @ 100056d0