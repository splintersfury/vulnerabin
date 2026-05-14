void __fastcall FUN_100278a0(undefined4 *param_1)

{
  int *piVar1;
  int iVar2;
  int *piVar3;
  
  piVar3 = (int *)*param_1;
  if (piVar3 != (int *)0x0) {
    LOCK();
    piVar1 = piVar3 + 2;
    iVar2 = *piVar1;
    *piVar1 = *piVar1 + -1;
    UNLOCK();
    if (iVar2 == 1) {
      if (*piVar3 != 0) {
        Ordinal_6(*piVar3);
        *piVar3 = 0;
      }
      if ((void *)piVar3[1] != (void *)0x0) {
        thunk_FUN_100330ca((void *)piVar3[1]);
        piVar3[1] = 0;
      }
      FUN_1002e346(piVar3);
    }
    *param_1 = 0;
  }
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_10027900 @ 10027900