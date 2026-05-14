void * __fastcall FUN_1000b910(void *param_1,uint *param_2,uint *param_3)

{
  code *pcVar1;
  uint *puVar2;
  void *pvVar3;
  void *local_30 [5];
  uint local_1c;
  void *local_18;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_1004e49d;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  local_18 = param_1;
  FUN_1000eb70(local_30,param_2);
  local_8 = 0;
  puVar2 = FUN_1000b650(local_30,param_3);
  FUN_1000eb70(param_1,puVar2);
  if (7 < local_1c) {
    pvVar3 = local_30[0];
    if (0xfff < local_1c * 2 + 2) {
      pvVar3 = *(void **)((int)local_30[0] + -4);
      if (0x1f < (uint)((int)local_30[0] + (-4 - (int)pvVar3))) {
        FUN_10032f7f();
        pcVar1 = (code *)swi(3);
        pvVar3 = (void *)(*pcVar1)();
        return pvVar3;
      }
    }
    FUN_1002e346(pvVar3);
  }
  ExceptionList = local_10;
  return param_1;
}


// FUNCTION_END

// FUNCTION_START: FUN_1000b9c0 @ 1000b9c0