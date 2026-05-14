void __fastcall FUN_10022170(int param_1)

{
  int *piVar1;
  void *pvVar2;
  int *piVar3;
  code *pcVar4;
  int iVar5;
  void *pvVar6;
  
  if (0xf < *(uint *)(param_1 + 0x264)) {
    pvVar2 = *(void **)(param_1 + 0x250);
    pvVar6 = pvVar2;
    if ((0xfff < *(uint *)(param_1 + 0x264) + 1) &&
       (pvVar6 = *(void **)((int)pvVar2 + -4), 0x1f < (uint)((int)pvVar2 + (-4 - (int)pvVar6)))) {
      FUN_10032f7f();
      pcVar4 = (code *)swi(3);
      (*pcVar4)();
      return;
    }
    FUN_1002e346(pvVar6);
  }
  *(undefined4 *)(param_1 + 0x260) = 0;
  *(undefined4 *)(param_1 + 0x264) = 0xf;
  *(undefined1 *)(param_1 + 0x250) = 0;
  piVar3 = *(int **)(param_1 + 4);
  if (piVar3 != (int *)0x0) {
    LOCK();
    iVar5 = piVar3[1] + -1;
    piVar3[1] = iVar5;
    UNLOCK();
    if (iVar5 == 0) {
      (**(code **)*piVar3)();
      LOCK();
      piVar1 = piVar3 + 2;
      iVar5 = *piVar1;
      *piVar1 = *piVar1 + -1;
      UNLOCK();
      if (iVar5 == 1) {
                    /* WARNING: Could not recover jumptable at 0x100221ec. Too many branches */
                    /* WARNING: Treating indirect jump as call */
        (**(code **)(*piVar3 + 4))();
        return;
      }
    }
  }
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_10022200 @ 10022200

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */