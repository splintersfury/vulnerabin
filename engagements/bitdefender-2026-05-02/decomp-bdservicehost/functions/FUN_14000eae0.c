undefined8 * FUN_14000eae0(undefined8 *param_1)

{
  HMODULE *ppHVar1;
  
  *(undefined4 *)(param_1 + 1) = 0;
  ppHVar1 = FUN_14000eb20();
  *param_1 = ppHVar1;
  LOCK();
  *(int *)(param_1 + 1) = *(int *)(param_1 + 1) + 1;
  UNLOCK();
  return param_1;
}


// FUNCTION_END

// FUNCTION_START: FUN_14000eb10 @ 14000eb10