void FUN_140003890(undefined8 *param_1)

{
  if ((HMODULE)*param_1 != (HMODULE)0x0) {
    FreeLibrary((HMODULE)*param_1);
    *param_1 = 0;
  }
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_1400038c0 @ 1400038c0