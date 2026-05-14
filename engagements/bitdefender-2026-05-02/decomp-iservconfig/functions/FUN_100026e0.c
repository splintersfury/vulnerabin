int __fastcall FUN_100026e0(int param_1)

{
  int iVar1;
  int iVar2;
  
  LOCK();
  iVar1 = *(int *)(param_1 + 4) + -1;
  *(int *)(param_1 + 4) = iVar1;
  UNLOCK();
  iVar2 = 0;
  if (iVar1 == 0) {
    iVar2 = param_1;
  }
  return iVar2;
}


// FUNCTION_END

// FUNCTION_START: FUN_10002700 @ 10002700