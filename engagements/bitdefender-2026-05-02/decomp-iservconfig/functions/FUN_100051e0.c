int __fastcall FUN_100051e0(undefined4 *param_1)

{
  int *piVar1;
  int iVar2;
  int iVar3;
  
  *param_1 = 0;
  piVar1 = param_1 + 1;
  LOCK();
  iVar3 = *piVar1 + -1;
  iVar2 = *piVar1;
  *piVar1 = iVar3;
  UNLOCK();
  while (-1 < iVar3) {
    FUN_10006030();
    LOCK();
    iVar3 = *piVar1 + -1;
    iVar2 = *piVar1;
    *piVar1 = iVar3;
    UNLOCK();
  }
  LOCK();
  *piVar1 = *piVar1 + 1;
  UNLOCK();
  return iVar2;
}


// FUNCTION_END

// FUNCTION_START: FUN_10005210 @ 10005210