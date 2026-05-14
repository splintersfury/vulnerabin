void FUN_140015820(longlong param_1)

{
  int iVar1;
  int iVar2;
  undefined1 auStackY_498 [32];
  HMODULE *local_458;
  int local_450;
  undefined4 local_448 [4];
  DWORD local_438;
  wchar_t local_434 [260];
  wchar_t local_22c [266];
  ulonglong local_18;
  
  local_18 = DAT_14007a060 ^ (ulonglong)auStackY_498;
  local_438 = timeGetTime();
  wcsncpy_s(local_434,0x102,L"service::StopService",0xffffffffffffffff);
  wcscat_s(local_434,0x104,L"()");
  wcsncpy_s(local_22c,0x104,L"service::StopService",0xffffffffffffffff);
  if (DAT_14007d500 + DAT_14007d504 != 0) {
    local_458 = FUN_14000eb20();
    LOCK();
    local_450 = 1;
    UNLOCK();
    if (local_458 == (HMODULE *)0x0) {
      local_458 = FUN_14000eb20();
      LOCK();
      local_450 = 2;
      UNLOCK();
    }
    local_448[0] = 0x20;
    FUN_1400019c0((longlong)local_458,1,local_448,&IMAGE_DOS_HEADER_140000000,local_22c,L"-> %s");
    LOCK();
    UNLOCK();
    iVar1 = local_450 + -1;
    iVar2 = local_450;
    while (-1 < iVar1) {
      local_450 = iVar2 + -1;
      FUN_140011e70();
      LOCK();
      UNLOCK();
      iVar1 = iVar2 + -2;
      iVar2 = local_450;
    }
    LOCK();
    UNLOCK();
  }
  if (*(HANDLE *)(param_1 + 8) != (HANDLE)0x0) {
    SetEvent(*(HANDLE *)(param_1 + 8));
  }
  FUN_140015270((longlong)&local_438);
  FUN_14002f160(local_18 ^ (ulonglong)auStackY_498);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_1400159b0 @ 1400159b0