void FUN_14000eaa0(undefined8 *param_1)

{
  int *piVar1;
  int iVar2;
  
  *param_1 = 0;
  piVar1 = (int *)(param_1 + 1);
  LOCK();
  iVar2 = *piVar1;
  *piVar1 = *piVar1 + -1;
  UNLOCK();
  while (-1 < iVar2 + -1) {
    FUN_140011e70();
    LOCK();
    iVar2 = *piVar1;
    *piVar1 = *piVar1 + -1;
    UNLOCK();
  }
  LOCK();
  *piVar1 = *piVar1 + 1;
  UNLOCK();
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_14000eae0 @ 14000eae0