undefined4 * __thiscall FUN_10009d30(void *this,undefined4 param_1,int *param_2)

{
  code *pcVar1;
  undefined4 *puVar2;
  void *pvVar3;
  void *local_2c [4];
  undefined4 local_1c;
  uint local_18;
  void *local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_1004e25d;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  local_1c = 0;
  local_18 = 0xf;
  local_2c[0] = (void *)0x0;
  local_14 = this;
  FUN_10008e70(local_2c,(uint *)&DAT_1005e237,0);
  local_8 = 0;
  FUN_100020f0(this,param_1,param_2,(uint *)local_2c);
  if (0xf < local_18) {
    pvVar3 = local_2c[0];
    if (0xfff < local_18 + 1) {
      pvVar3 = *(void **)((int)local_2c[0] + -4);
      if (0x1f < (uint)((int)local_2c[0] + (-4 - (int)pvVar3))) {
        FUN_10032f7f();
        pcVar1 = (code *)swi(3);
        puVar2 = (undefined4 *)(*pcVar1)();
        return puVar2;
      }
    }
    FUN_1002e346(pvVar3);
  }
  *(undefined ***)this = std::system_error::vftable;
  ExceptionList = local_10;
  return (undefined4 *)this;
}


// FUNCTION_END

// FUNCTION_START: FUN_10009df0 @ 10009df0