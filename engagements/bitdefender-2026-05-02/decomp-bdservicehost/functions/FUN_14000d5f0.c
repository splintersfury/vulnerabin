void FUN_14000d5f0(undefined8 *param_1)

{
  undefined8 *puVar1;
  
  puVar1 = (undefined8 *)*param_1;
  if (puVar1 != (undefined8 *)0x0) {
    if ((HMODULE)*puVar1 != (HMODULE)0x0) {
      FreeLibrary((HMODULE)*puVar1);
      *puVar1 = 0;
    }
    FUN_14002f180();
    return;
  }
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_14000d630 @ 14000d630