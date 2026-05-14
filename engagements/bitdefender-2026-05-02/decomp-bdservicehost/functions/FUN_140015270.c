void FUN_140015270(longlong param_1)

{
  int iVar1;
  int iVar2;
  undefined4 local_res10 [6];
  HMODULE *local_18;
  int local_10;
  
  if (DAT_14007d500 + DAT_14007d504 != 0) {
    local_18 = FUN_14000eb20();
    LOCK();
    local_10 = 1;
    UNLOCK();
    if (local_18 == (HMODULE *)0x0) {
      local_18 = FUN_14000eb20();
      LOCK();
      local_10 = 2;
      UNLOCK();
    }
    timeGetTime();
    local_res10[0] = 0x20;
    FUN_1400019c0((longlong)local_18,0xffff,local_res10,&IMAGE_DOS_HEADER_140000000,param_1 + 0x20c,
                  L"<- %s [%d]");
    LOCK();
    UNLOCK();
    iVar1 = local_10 + -1;
    iVar2 = local_10;
    while (-1 < iVar1) {
      local_10 = iVar2 + -1;
      FUN_140011e70();
      LOCK();
      UNLOCK();
      iVar1 = iVar2 + -2;
      iVar2 = local_10;
    }
    LOCK();
    UNLOCK();
  }
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_140015360 @ 140015360