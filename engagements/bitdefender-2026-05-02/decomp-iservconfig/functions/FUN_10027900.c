undefined4 * __thiscall FUN_10027900(void *this,int param_1)

{
  int *piVar1;
  code *pcVar2;
  uint uVar3;
  int *piVar4;
  int iVar5;
  undefined4 *puVar6;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_10050404;
  local_10 = ExceptionList;
  uVar3 = DAT_10069054 ^ (uint)&stack0xfffffffc;
                    /* WARNING: Load size is inaccurate */
  if ((param_1 == 0) || (piVar4 = *this, piVar4 == (int *)0x0)) {
                    /* WARNING: Load size is inaccurate */
    piVar4 = *this;
    ExceptionList = &local_10;
    if (piVar4 != (int *)0x0) goto LAB_10027946;
  }
  else {
    if (*piVar4 == param_1) {
      return (undefined4 *)this;
    }
LAB_10027946:
    LOCK();
    piVar1 = piVar4 + 2;
    iVar5 = *piVar1;
    ExceptionList = &local_10;
    *piVar1 = *piVar1 + -1;
    UNLOCK();
    if (iVar5 == 1) {
      if (*piVar4 != 0) {
        Ordinal_6(*piVar4,uVar3);
        *piVar4 = 0;
      }
      if ((void *)piVar4[1] != (void *)0x0) {
        thunk_FUN_100330ca((void *)piVar4[1]);
        piVar4[1] = 0;
      }
      FUN_1002e346(piVar4);
    }
    *(undefined4 *)this = 0;
  }
  piVar4 = (int *)operator_new(0xc);
  local_8 = 0;
  if (piVar4 == (int *)0x0) {
    piVar4 = (int *)0x0;
  }
  else {
    piVar4[0] = 0;
    piVar4[1] = 0;
    piVar4[2] = 0;
    piVar4[1] = 0;
    piVar4[2] = 1;
    iVar5 = Ordinal_2(param_1);
    *piVar4 = iVar5;
    if ((iVar5 == 0) && (param_1 != 0)) {
      FUN_1002f620(0x8007000e);
      goto LAB_10027a04;
    }
  }
  local_8 = 0xffffffff;
  *(int **)this = piVar4;
  if (piVar4 != (int *)0x0) {
    ExceptionList = local_10;
    return (undefined4 *)this;
  }
LAB_10027a04:
  FUN_1002f620(0x8007000e);
  pcVar2 = (code *)swi(3);
  puVar6 = (undefined4 *)(*pcVar2)();
  return puVar6;
}


// FUNCTION_END

// FUNCTION_START: FUN_10027a10 @ 10027a10