void __fastcall FUN_1000e820(int param_1)

{
  int *piVar1;
  int *piVar2;
  int iVar3;
  
  piVar2 = *(int **)(param_1 + 4);
  if (piVar2 != (int *)0x0) {
    LOCK();
    iVar3 = piVar2[1] + -1;
    piVar2[1] = iVar3;
    UNLOCK();
    if (iVar3 == 0) {
      (**(code **)*piVar2)();
      LOCK();
      piVar1 = piVar2 + 2;
      iVar3 = *piVar1;
      *piVar1 = *piVar1 + -1;
      UNLOCK();
      if (iVar3 == 1) {
                    /* WARNING: Could not recover jumptable at 0x1000e849. Too many branches */
                    /* WARNING: Treating indirect jump as call */
        (**(code **)(*piVar2 + 4))();
        return;
      }
    }
  }
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_1000e850 @ 1000e850

/* WARNING: Removing unreachable block (ram,0x1000e897) */
/* WARNING: Removing unreachable block (ram,0x1000e8a1) */