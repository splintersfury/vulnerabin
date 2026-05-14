undefined4 * __thiscall FUN_100022f0(void *this,uint *param_1,undefined4 param_2,int *param_3)

{
  code *pcVar1;
  uint uVar2;
  undefined4 *puVar3;
  uint *puVar4;
  void *pvVar5;
  void *local_30 [4];
  undefined4 local_20;
  uint local_1c;
  void *local_18;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_1004d9ad;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  local_20 = 0;
  local_1c = 0xf;
  local_30[0] = (void *)0x0;
  puVar4 = param_1;
  do {
    uVar2 = *puVar4;
    puVar4 = (uint *)((int)puVar4 + 1);
  } while ((char)uVar2 != '\0');
  local_18 = this;
  FUN_10008e70(local_30,param_1,(int)puVar4 - ((int)param_1 + 1));
  local_8 = 0;
  FUN_100020f0(this,param_2,param_3,(uint *)local_30);
  if (0xf < local_1c) {
    pvVar5 = local_30[0];
    if (0xfff < local_1c + 1) {
      pvVar5 = *(void **)((int)local_30[0] + -4);
      if (0x1f < (uint)((int)local_30[0] + (-4 - (int)pvVar5))) {
        FUN_10032f7f();
        pcVar1 = (code *)swi(3);
        puVar3 = (undefined4 *)(*pcVar1)();
        return puVar3;
      }
    }
    FUN_1002e346(pvVar5);
  }
  *(undefined ***)this = std::system_error::vftable;
  ExceptionList = local_10;
  return (undefined4 *)this;
}


// FUNCTION_END

// FUNCTION_START: FUN_100023c0 @ 100023c0