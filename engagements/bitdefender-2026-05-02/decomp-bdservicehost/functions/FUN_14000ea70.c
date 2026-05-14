longlong FUN_14000ea70(longlong *param_1)

{
  HMODULE *ppHVar1;
  
  if (*param_1 == 0) {
    ppHVar1 = FUN_14000eb20();
    *param_1 = (longlong)ppHVar1;
    LOCK();
    *(int *)(param_1 + 1) = (int)param_1[1] + 1;
    UNLOCK();
    return *param_1;
  }
  return *param_1;
}


// FUNCTION_END

// FUNCTION_START: FUN_14000eaa0 @ 14000eaa0