void FUN_140002450(longlong param_1)

{
  LOCK();
  *(int *)(param_1 + 8) = *(int *)(param_1 + 8) + 1;
  UNLOCK();
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_140002460 @ 140002460