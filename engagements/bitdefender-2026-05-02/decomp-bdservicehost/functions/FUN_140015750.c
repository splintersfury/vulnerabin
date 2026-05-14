void FUN_140015750(undefined8 *param_1)

{
  int *piVar1;
  int iVar2;
  
  *param_1 = service::vftable;
  if ((HANDLE)param_1[1] != (HANDLE)0x0) {
    CloseHandle((HANDLE)param_1[1]);
    param_1[1] = 0;
  }
  if ((param_1[5] != 0) && (param_1[4] != 0)) {
    (*(code *)PTR__guard_dispatch_icall_14005b538)();
    param_1[5] = 0;
    param_1[4] = 0;
  }
  param_1[6] = 0;
  LOCK();
  piVar1 = (int *)(param_1 + 7);
  iVar2 = *piVar1;
  *piVar1 = *piVar1 + -1;
  UNLOCK();
  while (-1 < iVar2 + -1) {
    FUN_140011e70();
    LOCK();
    piVar1 = (int *)(param_1 + 7);
    iVar2 = *piVar1;
    *piVar1 = *piVar1 + -1;
    UNLOCK();
  }
  LOCK();
  *(int *)(param_1 + 7) = *(int *)(param_1 + 7) + 1;
  UNLOCK();
  if ((HMODULE)param_1[3] != (HMODULE)0x0) {
    FreeLibrary((HMODULE)param_1[3]);
    param_1[3] = 0;
  }
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_1400157f0 @ 1400157f0