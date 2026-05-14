void FUN_14000a4d0(undefined8 *param_1)

{
  if ((SC_HANDLE)*param_1 != (SC_HANDLE)0x0) {
    CloseServiceHandle((SC_HANDLE)*param_1);
    *param_1 = 0;
  }
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_14000a500 @ 14000a500