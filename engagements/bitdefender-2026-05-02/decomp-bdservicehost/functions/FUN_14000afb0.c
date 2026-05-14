void FUN_14000afb0(void)

{
  int iVar1;
  wint_t wVar2;
  int iVar3;
  undefined8 uVar4;
  wchar_t *pwVar5;
  IMAGE_DOS_HEADER *pIVar6;
  undefined1 auStackY_5d8 [32];
  HMODULE *local_598;
  int local_590;
  undefined4 local_588 [68];
  undefined **local_478;
  HANDLE pvStack_470;
  undefined8 local_468;
  HMODULE pHStack_460;
  longlong local_458;
  longlong lStack_450;
  undefined8 local_448;
  undefined8 uStack_440;
  DWORD local_438;
  wchar_t local_434 [260];
  wchar_t local_22c [266];
  ulonglong local_18;
  
  local_18 = DAT_14007a060 ^ (ulonglong)auStackY_5d8;
  local_478 = (undefined **)0x0;
  pvStack_470 = (HANDLE)0x0;
  local_468 = 0;
  pHStack_460 = (HMODULE)0x0;
  local_458 = 0;
  lStack_450 = 0;
  local_448 = 0;
  uStack_440 = 0;
  FUN_140015360(&local_478);
  DAT_14007acf8 = &local_478;
  DAT_14007ad00 = 1;
  local_438 = timeGetTime();
  wcsncpy_s(local_434,0x102,L"service::run_as_executable",0xffffffffffffffff);
  wcscat_s(local_434,0x104,L"()");
  pIVar6 = (IMAGE_DOS_HEADER *)0xffffffffffffffff;
  pwVar5 = L"service::run_as_executable";
  uVar4 = 0x104;
  wcsncpy_s(local_22c,0x104,L"service::run_as_executable",0xffffffffffffffff);
  if (DAT_14007d500 + DAT_14007d504 != 0) {
    local_598 = FUN_14000eb20();
    LOCK();
    local_590 = 1;
    UNLOCK();
    if (local_598 == (HMODULE *)0x0) {
      local_598 = FUN_14000eb20();
      LOCK();
      local_590 = 2;
      UNLOCK();
    }
    local_588[0] = 0x20;
    pIVar6 = &IMAGE_DOS_HEADER_140000000;
    pwVar5 = (wchar_t *)local_588;
    uVar4 = 1;
    FUN_1400019c0((longlong)local_598,1,pwVar5,&IMAGE_DOS_HEADER_140000000,local_22c,L"-> %s");
    LOCK();
    UNLOCK();
    iVar3 = local_590 + -1;
    iVar1 = local_590;
    while (-1 < iVar3) {
      local_590 = iVar1 + -1;
      FUN_140011e70();
      LOCK();
      UNLOCK();
      iVar3 = iVar1 + -2;
      iVar1 = local_590;
    }
    LOCK();
    UNLOCK();
  }
  AllocConsole();
  FUN_1400178b0(0x14006bb20,uVar4,pwVar5,pIVar6);
  (*(code *)PTR__guard_dispatch_icall_14005b538)(local_458,&local_478);
  while ((iVar3 = _kbhit(), iVar3 == 0 || (wVar2 = _getwch(), wVar2 != 0x78))) {
    Sleep(10);
  }
  (*(code *)PTR__guard_dispatch_icall_14005b538)();
  FreeConsole();
  FUN_140015270((longlong)&local_438);
  DAT_14007ad00 = 0;
  local_478 = service::vftable;
  if (pvStack_470 != (HANDLE)0x0) {
    CloseHandle(pvStack_470);
    pvStack_470 = (HANDLE)0x0;
  }
  if ((lStack_450 != 0) && (local_458 != 0)) {
    (*(code *)PTR__guard_dispatch_icall_14005b538)();
    lStack_450 = 0;
    local_458 = 0;
  }
  local_448 = 0;
  LOCK();
  UNLOCK();
  iVar3 = (int)uStack_440;
  while (uStack_440._0_4_ = iVar3 + -1, -1 < iVar3 + -1) {
    FUN_140011e70();
    LOCK();
    UNLOCK();
    iVar3 = (int)uStack_440;
  }
  LOCK();
  uStack_440 = CONCAT44(uStack_440._4_4_,iVar3);
  UNLOCK();
  if (pHStack_460 != (HMODULE)0x0) {
    FreeLibrary(pHStack_460);
  }
  FUN_14002f160(local_18 ^ (ulonglong)auStackY_5d8);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_14000b2a0 @ 14000b2a0