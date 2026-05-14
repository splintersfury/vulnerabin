void FUN_140006e00(char *param_1)

{
  if ((*param_1 == '\0') || (*(longlong *)(param_1 + 8) != 0)) {
    FUN_140011e70();
  }
  if (*(HMODULE *)(param_1 + 8) != (HMODULE)0x0) {
    FreeLibrary(*(HMODULE *)(param_1 + 8));
    param_1[8] = '\0';
    param_1[9] = '\0';
    param_1[10] = '\0';
    param_1[0xb] = '\0';
    param_1[0xc] = '\0';
    param_1[0xd] = '\0';
    param_1[0xe] = '\0';
    param_1[0xf] = '\0';
  }
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_140006e40 @ 140006e40