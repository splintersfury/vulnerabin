int __fastcall FUN_1000c320(int param_1)

{
  HMODULE *local_1c;
  int local_18;
  undefined4 local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 uStack_8;
  
  uStack_8 = 0xffffffff;
  puStack_c = &LAB_1004e5c0;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  local_18 = DAT_1006b614 + DAT_1006b618;
  if (local_18 != 0) {
    local_1c = FUN_10005210();
    LOCK();
    local_18 = 1;
    UNLOCK();
    if (local_1c == (HMODULE *)0x0) {
      local_1c = FUN_10005210();
      LOCK();
      local_18 = 2;
      UNLOCK();
    }
    timeGetTime();
    local_14 = 0x20;
    FUN_10003200((int)local_1c,0xffffffff,&local_14,0x10000000,param_1 + 0x20c,L"<- %s [%d]");
    LOCK();
    UNLOCK();
    while (-1 < local_18 + -1) {
      FUN_10006030();
      LOCK();
      UNLOCK();
      local_18 = local_18 + -1;
    }
    LOCK();
    UNLOCK();
  }
  ExceptionList = local_10;
  return local_18;
}


// FUNCTION_END

// FUNCTION_START: FUN_1000c3f0 @ 1000c3f0