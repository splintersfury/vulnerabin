void __fastcall FUN_100026d0(int param_1)

{
  LOCK();
  *(int *)(param_1 + 4) = *(int *)(param_1 + 4) + 1;
  UNLOCK();
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_100026e0 @ 100026e0