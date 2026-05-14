void FUN_140016190(longlong param_1,DWORD param_2,DWORD param_3,DWORD param_4)

{
  int iVar1;
  int iVar2;
  DWORD DVar3;
  undefined1 auStackY_4e8 [32];
  HMODULE *local_4a8;
  int local_4a0;
  undefined4 local_498 [2];
  _SERVICE_STATUS local_490;
  DWORD local_468;
  wchar_t local_464 [260];
  wchar_t local_25c [266];
  ulonglong local_48;
  
  local_48 = DAT_14007a060 ^ (ulonglong)auStackY_4e8;
  local_468 = timeGetTime();
  wcsncpy_s(local_464,0x102,L"service::report_status",0xffffffffffffffff);
  wcscat_s(local_464,0x104,L"()");
  wcsncpy_s(local_25c,0x104,L"service::report_status",0xffffffffffffffff);
  DVar3 = 0;
  if (DAT_14007d500 + DAT_14007d504 != 0) {
    local_4a8 = FUN_14000eb20();
    LOCK();
    local_4a0 = 1;
    UNLOCK();
    if (local_4a8 == (HMODULE *)0x0) {
      local_4a8 = FUN_14000eb20();
      LOCK();
      local_4a0 = 2;
      UNLOCK();
    }
    local_498[0] = 0x20;
    FUN_1400019c0((longlong)local_4a8,1,local_498,&IMAGE_DOS_HEADER_140000000,local_25c,L"-> %s");
    LOCK();
    UNLOCK();
    iVar1 = local_4a0 + -1;
    iVar2 = local_4a0;
    while (-1 < iVar1) {
      local_4a0 = iVar2 + -1;
      FUN_140011e70();
      LOCK();
      UNLOCK();
      iVar1 = iVar2 + -2;
      iVar2 = local_4a0;
    }
    LOCK();
    UNLOCK();
  }
  if ((param_2 != 4) && (param_2 != 1)) {
    DVar3 = DAT_14007d518 + 1;
  }
  local_490.dwServiceSpecificExitCode = 0;
  if (param_2 == 2) {
    local_490.dwControlsAccepted = 0;
  }
  else {
    local_490.dwControlsAccepted = *(DWORD *)(DAT_14007acf0 + 0xa0);
  }
  local_490.dwServiceType = 0x10;
  DAT_14007d518 = DVar3;
  local_490.dwCurrentState = param_2;
  local_490.dwWin32ExitCode = param_3;
  local_490.dwCheckPoint = DVar3;
  local_490.dwWaitHint = param_4;
  SetServiceStatus(*(SERVICE_STATUS_HANDLE *)(param_1 + 0x10),&local_490);
  FUN_140015270((longlong)&local_468);
  FUN_14002f160(local_48 ^ (ulonglong)auStackY_4e8);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_140016380 @ 140016380