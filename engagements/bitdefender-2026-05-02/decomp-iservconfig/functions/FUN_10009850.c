undefined4 __fastcall FUN_10009850(int param_1)

{
  int *piVar1;
  void *pvVar2;
  undefined4 *puVar3;
  int local_8;
  
  if (*(int *)(param_1 + 8) == 0) {
    local_8 = param_1;
    puVar3 = (undefined4 *)operator_new(0x30);
    __Mtx_init_in_situ(puVar3,2);
    piVar1 = (int *)(param_1 + 4);
    if (piVar1 == &local_8) {
      __Mtx_destroy_in_situ((int)puVar3);
      FUN_1002e346(puVar3);
    }
    else {
      pvVar2 = (void *)*piVar1;
      *piVar1 = (int)puVar3;
      if (pvVar2 != (void *)0x0) {
        __Mtx_destroy_in_situ((int)pvVar2);
        FUN_1002e346(pvVar2);
        return 0;
      }
    }
  }
  return 0;
}


// FUNCTION_END

// FUNCTION_START: FUN_100098c0 @ 100098c0