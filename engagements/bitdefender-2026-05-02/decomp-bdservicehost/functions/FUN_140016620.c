void FUN_140016620(void)

{
  longlong lVar1;
  int iVar2;
  int iVar3;
  longlong *plVar4;
  longlong *plVar5;
  undefined1 auStackY_4d8 [32];
  HMODULE *local_498;
  int local_490;
  undefined4 local_488 [4];
  float local_478 [2];
  longlong *plStack_470;
  undefined8 local_468;
  undefined8 uStack_460;
  undefined8 local_458;
  undefined8 uStack_450;
  undefined8 local_448;
  undefined8 uStack_440;
  DWORD local_438;
  wchar_t local_434 [260];
  wchar_t local_22c [266];
  ulonglong local_18;
  
  local_18 = DAT_14007a060 ^ (ulonglong)auStackY_4d8;
  local_438 = timeGetTime();
  wcsncpy_s(local_434,0x102,L"service::unregister_service_events",0xffffffffffffffff);
  wcscat_s(local_434,0x104,L"()");
  wcsncpy_s(local_22c,0x104,L"service::unregister_service_events",0xffffffffffffffff);
  if (DAT_14007d500 + DAT_14007d504 != 0) {
    local_498 = FUN_14000eb20();
    LOCK();
    local_490 = 1;
    UNLOCK();
    if (local_498 == (HMODULE *)0x0) {
      local_498 = FUN_14000eb20();
      LOCK();
      local_490 = 2;
      UNLOCK();
    }
    local_488[0] = 0x20;
    FUN_1400019c0((longlong)local_498,1,local_488,&IMAGE_DOS_HEADER_140000000,local_22c,L"-> %s");
    LOCK();
    UNLOCK();
    iVar2 = local_490 + -1;
    iVar3 = local_490;
    while (-1 < iVar2) {
      local_490 = iVar3 + -1;
      FUN_140011e70();
      LOCK();
      UNLOCK();
      iVar2 = iVar3 + -2;
      iVar3 = local_490;
    }
    LOCK();
    UNLOCK();
  }
  local_478[0] = 0.0;
  local_478[1] = 0.0;
  plStack_470 = (longlong *)0x0;
  local_468 = 0;
  uStack_460 = 0;
  local_458 = 0;
  uStack_450 = 0;
  local_448 = 0;
  uStack_440 = 0;
  FUN_140016ed0(local_478,(float *)(DAT_14007acf0 + 0xa8));
  plVar5 = (longlong *)*plStack_470;
  plVar4 = plStack_470;
  if (plVar5 != plStack_470) {
    do {
      lVar1 = plVar5[3];
      if (lVar1 != 0) {
        (*(code *)PTR__guard_dispatch_icall_14005b538)(lVar1);
        (*(code *)PTR__guard_dispatch_icall_14005b538)(lVar1,1);
        plVar4 = plStack_470;
      }
      plVar5 = (longlong *)*plVar5;
    } while (plVar5 != plVar4);
  }
  FUN_140010a90((longlong)local_478);
  FUN_140015270((longlong)&local_438);
  FUN_14002f160(local_18 ^ (ulonglong)auStackY_4d8);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_140016820 @ 140016820

/* WARNING: Type propagation algorithm not settling */
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */