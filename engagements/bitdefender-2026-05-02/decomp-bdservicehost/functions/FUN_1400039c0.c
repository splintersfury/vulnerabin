void FUN_1400039c0(undefined8 *param_1)

{
  if ((HANDLE)*param_1 != (HANDLE)0xffffffffffffffff) {
    CloseHandle((HANDLE)*param_1);
    *param_1 = 0xffffffffffffffff;
  }
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_1400039f0 @ 1400039f0