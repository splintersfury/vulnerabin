void __fastcall FUN_100098c0(int param_1)

{
  void *pvVar1;
  
  if (*(int *)(param_1 + 8) == 0) {
    pvVar1 = *(void **)(param_1 + 4);
    *(undefined4 *)(param_1 + 4) = 0;
    if (pvVar1 != (void *)0x0) {
      __Mtx_destroy_in_situ((int)pvVar1);
      FUN_1002e346(pvVar1);
    }
  }
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_100098f0 @ 100098f0