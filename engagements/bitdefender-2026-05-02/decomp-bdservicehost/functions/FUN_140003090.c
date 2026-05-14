void FUN_140003090(longlong *param_1)

{
  ios_base *piVar1;
  int iVar2;
  code *pcVar3;
  int iVar4;
  HMODULE *local_48;
  int local_40;
  undefined2 local_38;
  undefined6 uStack_36;
  undefined8 local_28;
  ulonglong local_20;
  
  piVar1 = (ios_base *)(param_1 + 0x13);
  *(undefined ***)(piVar1 + (longlong)*(int *)(*param_1 + 4) + -0x98) = logger_stream::vftable;
  *(int *)(piVar1 + (longlong)*(int *)(*param_1 + 4) + -0x9c) = *(int *)(*param_1 + 4) + -0x98;
  if (((char)param_1[0x10] != '\0') && (DAT_14007d500 + DAT_14007d504 != 0)) {
    local_48 = FUN_14000eb20();
    LOCK();
    local_40 = 1;
    UNLOCK();
    if (local_48 == (HMODULE *)0x0) {
      local_48 = FUN_14000eb20();
      LOCK();
      local_40 = 2;
      UNLOCK();
    }
    FUN_1400100a0((longlong)(param_1 + 1),(longlong *)&local_38);
    FUN_1400019c0((longlong)local_48,0,(longlong)param_1 + 0x84,&IMAGE_DOS_HEADER_140000000,
                  param_1[0x11],&DAT_14006a9d0);
    if (7 < local_20) {
      if ((0xfff < local_20 * 2 + 2) &&
         (0x1f < (CONCAT62(uStack_36,local_38) - *(longlong *)(CONCAT62(uStack_36,local_38) + -8)) -
                 8U)) {
        FUN_140035d28();
        pcVar3 = (code *)swi(3);
        (*pcVar3)();
        return;
      }
      FUN_14002f180();
    }
    local_28 = 0;
    local_20 = 7;
    local_38 = 0;
    LOCK();
    UNLOCK();
    iVar2 = local_40 + -1;
    iVar4 = local_40;
    while (-1 < iVar2) {
      local_40 = iVar4 + -1;
      FUN_140011e70();
      LOCK();
      UNLOCK();
      iVar2 = iVar4 + -2;
      iVar4 = local_40;
    }
    LOCK();
    UNLOCK();
  }
  FUN_14000e180((longlong)(param_1 + 0x11));
  *(undefined ***)piVar1 = std::ios_base::vftable;
  std::ios_base::_Ios_base_dtor(piVar1);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_140003230 @ 140003230