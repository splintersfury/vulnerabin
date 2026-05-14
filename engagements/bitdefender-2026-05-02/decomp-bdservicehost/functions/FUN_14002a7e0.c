void FUN_14002a7e0(undefined8 *param_1)

{
  if (((*(char *)(param_1 + 1) != -1) && (*(char *)(param_1 + 1) == '\0')) &&
     ((SC_HANDLE)*param_1 != (SC_HANDLE)0x0)) {
                    /* WARNING: Could not recover jumptable at 0x00014002a7f9. Too many branches */
                    /* WARNING: Treating indirect jump as call */
    CloseServiceHandle((SC_HANDLE)*param_1);
    return;
  }
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_14002a810 @ 14002a810