void FUN_1400159d0(longlong *param_1)

{
  int iVar1;
  int iVar2;
  DWORD DVar3;
  SERVICE_STATUS_HANDLE pSVar4;
  LPCWSTR lpServiceName;
  undefined1 auStackY_4e8 [32];
  HMODULE *local_4a8;
  int local_4a0;
  undefined4 local_498 [2];
  undefined8 local_490 [3];
  tagMSG local_478;
  DWORD local_448;
  wchar_t local_444 [260];
  wchar_t local_23c [266];
  ulonglong local_28;
  
  local_28 = DAT_14007a060 ^ (ulonglong)auStackY_4e8;
  local_448 = timeGetTime();
  wcsncpy_s(local_444,0x102,L"service::run_as_service",0xffffffffffffffff);
  wcscat_s(local_444,0x104,L"()");
  wcsncpy_s(local_23c,0x104,L"service::run_as_service",0xffffffffffffffff);
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
    FUN_1400019c0((longlong)local_4a8,1,local_498,&IMAGE_DOS_HEADER_140000000,local_23c,L"-> %s");
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
  lpServiceName = DAT_14007acf0;
  if (7 < *(ulonglong *)(DAT_14007acf0 + 0xc)) {
    lpServiceName = *(LPCWSTR *)DAT_14007acf0;
  }
  pSVar4 = RegisterServiceCtrlHandlerExW(lpServiceName,FUN_140016eb0,param_1);
  param_1[2] = (longlong)pSVar4;
  if (pSVar4 == (SERVICE_STATUS_HANDLE)0x0) {
    FUN_140001ab0(local_490,0x14006bac0);
                    /* WARNING: Subroutine does not return */
    _CxxThrowException(local_490,(ThrowInfo *)&DAT_140077818);
  }
  FUN_140016380((longlong)param_1);
  FUN_140016190((longlong)param_1,2,0,3000);
  FUN_140016b80(param_1);
  (*(code *)PTR__guard_dispatch_icall_14005b538)(param_1[4],param_1);
  FUN_140016190((longlong)param_1,4,0,0);
  local_478.hwnd = (HWND)0x0;
  local_478.message = 0;
  local_478._12_4_ = 0;
  local_478.wParam = 0;
  local_478.lParam = 0;
  local_478.time = 0;
  local_478.pt.x = 0;
  local_478.pt.y = 0;
  local_478._44_4_ = 0;
  DVar3 = MsgWaitForMultipleObjectsEx(1,(HANDLE *)(param_1 + 1),0xffffffff,0x1cbf,0);
  while (DVar3 != 0) {
    GetMessageW(&local_478,(HWND)0x0,0,0);
    DispatchMessageW(&local_478);
    DVar3 = MsgWaitForMultipleObjectsEx(1,(HANDLE *)(param_1 + 1),0xffffffff,0x1cbf,0);
  }
  FUN_140016190((longlong)param_1,3,0,0);
  (*(code *)PTR__guard_dispatch_icall_14005b538)();
  FUN_140016620();
  FUN_140016190((longlong)param_1,1,0,0);
  FUN_140015270((longlong)&local_448);
  FUN_14002f160(local_28 ^ (ulonglong)auStackY_4e8);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_140015ca0 @ 140015ca0