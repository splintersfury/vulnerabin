void FUN_140016380(longlong param_1)

{
  int iVar1;
  int iVar2;
  bool bVar3;
  longlong *plVar4;
  longlong *plVar5;
  undefined1 auStackY_4f8 [32];
  HMODULE *local_4b0;
  int local_4a8;
  HMODULE *local_4a0;
  int local_498;
  undefined4 local_490;
  undefined4 local_48c;
  undefined8 local_488;
  longlong *plStack_480;
  longlong local_478;
  undefined8 uStack_470;
  undefined8 local_468;
  undefined8 uStack_460;
  undefined8 local_458;
  undefined8 uStack_450;
  DWORD local_448;
  wchar_t local_444 [260];
  wchar_t local_23c [266];
  ulonglong local_28;
  
  local_28 = DAT_14007a060 ^ (ulonglong)auStackY_4f8;
  bVar3 = false;
  local_448 = timeGetTime();
  wcsncpy_s(local_444,0x102,L"service::register_service_events",0xffffffffffffffff);
  wcscat_s(local_444,0x104,L"()");
  wcsncpy_s(local_23c,0x104,L"service::register_service_events",0xffffffffffffffff);
  if (DAT_14007d500 + DAT_14007d504 != 0) {
    local_4b0 = FUN_14000eb20();
    LOCK();
    local_4a8 = 1;
    UNLOCK();
    if (local_4b0 == (HMODULE *)0x0) {
      local_4b0 = FUN_14000eb20();
      LOCK();
      local_4a8 = 2;
      UNLOCK();
    }
    local_490 = 0x20;
    FUN_1400019c0((longlong)local_4b0,1,&local_490,&IMAGE_DOS_HEADER_140000000,local_23c,L"-> %s");
    LOCK();
    UNLOCK();
    iVar1 = local_4a8 + -1;
    iVar2 = local_4a8;
    while (-1 < iVar1) {
      local_4a8 = iVar2 + -1;
      FUN_140011e70();
      LOCK();
      UNLOCK();
      iVar1 = iVar2 + -2;
      iVar2 = local_4a8;
    }
    LOCK();
    UNLOCK();
  }
  local_488 = 0;
  plStack_480 = (longlong *)0x0;
  local_478 = 0;
  uStack_470 = 0;
  local_468 = 0;
  uStack_460 = 0;
  local_458 = 0;
  uStack_450 = 0;
  FUN_140016ed0((float *)&local_488,(float *)(DAT_14007acf0 + 0xa8));
  if (local_478 == 0) {
    if (DAT_14007d500 + DAT_14007d504 != 0) {
      local_4a0 = FUN_14000eb20();
      LOCK();
      local_498 = 1;
      UNLOCK();
      bVar3 = true;
      if (local_4a0 == (HMODULE *)0x0) {
        local_4a0 = FUN_14000eb20();
        LOCK();
        local_498 = 2;
        UNLOCK();
      }
      local_48c = 0x10;
      FUN_1400019c0((longlong)local_4a0,0,&local_48c,&IMAGE_DOS_HEADER_140000000,
                    L"service::register_service_events",L"events map is empty");
    }
    if (bVar3) {
      LOCK();
      UNLOCK();
      iVar1 = local_498 + -1;
      iVar2 = local_498;
      while (-1 < iVar1) {
        local_498 = iVar2 + -1;
        FUN_140011e70();
        LOCK();
        UNLOCK();
        iVar1 = iVar2 + -2;
        iVar2 = local_498;
      }
      LOCK();
      UNLOCK();
    }
  }
  plVar5 = (longlong *)*plStack_480;
  plVar4 = plStack_480;
  if (plVar5 != plStack_480) {
    do {
      if (plVar5[3] != 0) {
        (*(code *)PTR__guard_dispatch_icall_14005b538)(plVar5[3],*(undefined8 *)(param_1 + 0x10));
        plVar4 = plStack_480;
      }
      plVar5 = (longlong *)*plVar5;
    } while (plVar5 != plVar4);
  }
  FUN_140010a90((longlong)&local_488);
  FUN_140015270((longlong)&local_448);
  FUN_14002f160(local_28 ^ (ulonglong)auStackY_4f8);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_140016620 @ 140016620