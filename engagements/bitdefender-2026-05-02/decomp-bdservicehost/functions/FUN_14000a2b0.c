undefined * FUN_14000a2b0(undefined8 param_1,undefined8 param_2,undefined8 param_3)

{
  undefined8 uVar1;
  
  uVar1 = 4;
                    /* WARNING: Load size is inaccurate */
  if (*(int *)(*ThreadLocalStoragePointer + 4) < DAT_14007d610) {
    _Init_thread_header(&DAT_14007d610);
    if (DAT_14007d610 == -1) {
      FUN_140009ba0((longlong *)&DAT_14007d618,uVar1,param_3);
      atexit(FUN_14005a3a0);
      _Init_thread_footer(&DAT_14007d610);
      return &DAT_14007d618;
    }
  }
  return &DAT_14007d618;
}


// FUNCTION_END

// FUNCTION_START: FUN_14000a330 @ 14000a330

/* WARNING: Type propagation algorithm not settling */
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */