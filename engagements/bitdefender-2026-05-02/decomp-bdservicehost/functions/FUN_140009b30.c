void FUN_140009b30(undefined8 *param_1)

{
  if (param_1[3] != 0) {
    (*(code *)PTR__guard_dispatch_icall_14005b538)();
  }
  if (param_1[2] != 0) {
    (*(code *)PTR__guard_dispatch_icall_14005b538)(param_1[2],1);
  }
  if ((HMODULE)param_1[1] != (HMODULE)0x0) {
    FreeLibrary((HMODULE)param_1[1]);
    param_1[1] = 0;
  }
  if ((HMODULE)*param_1 != (HMODULE)0x0) {
    FreeLibrary((HMODULE)*param_1);
    *param_1 = 0;
  }
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_140009ba0 @ 140009ba0