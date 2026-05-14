void FUN_14002ac10(undefined8 *param_1,SC_HANDLE param_2,DWORD param_3,LPCWSTR *param_4)

{
  int iVar1;
  int iVar2;
  char cVar3;
  BOOL BVar4;
  DWORD DVar5;
  undefined1 auStackY_518 [32];
  HMODULE *local_4d8;
  int local_4d0;
  undefined4 local_4c8 [2];
  longlong local_4c0;
  undefined8 uStack_4b8;
  undefined8 local_4b0;
  undefined8 uStack_4a8;
  undefined8 *local_4a0;
  DWORD local_498;
  undefined4 uStack_494;
  undefined **ppuStack_490;
  DWORD local_468;
  wchar_t local_464 [260];
  wchar_t local_25c [266];
  ulonglong local_48;
  
  local_48 = DAT_14007a060 ^ (ulonglong)auStackY_518;
  local_4a0 = param_1;
  local_468 = timeGetTime();
  wcsncpy_s(local_464,0x102,L"start_service",0xffffffffffffffff);
  wcscat_s(local_464,0x104,L"()");
  wcsncpy_s(local_25c,0x104,L"start_service",0xffffffffffffffff);
  if (DAT_14007d500 + DAT_14007d504 != 0) {
    local_4d8 = FUN_14000eb20();
    LOCK();
    local_4d0 = 1;
    UNLOCK();
    if (local_4d8 == (HMODULE *)0x0) {
      local_4d8 = FUN_14000eb20();
      LOCK();
      local_4d0 = 2;
      UNLOCK();
    }
    local_4c8[0] = 0x20;
    FUN_1400019c0((longlong)local_4d8,1,local_4c8,&IMAGE_DOS_HEADER_140000000,local_25c,L"-> %s");
    LOCK();
    UNLOCK();
    iVar1 = local_4d0 + -1;
    iVar2 = local_4d0;
    while (-1 < iVar1) {
      local_4d0 = iVar2 + -1;
      FUN_140011e70();
      LOCK();
      UNLOCK();
      iVar1 = iVar2 + -2;
      iVar2 = local_4d0;
    }
    LOCK();
    UNLOCK();
  }
  cVar3 = FUN_14002c1f0(param_2,10000);
  if (cVar3 == '\0') {
    local_4c0 = 0;
    local_4b0 = 0;
    uStack_4a8 = 0xf;
    FUN_1400106a0(&local_4c0,(undefined8 *)"wait_service_to_stop failed",0x1b);
    local_498 = 0x5b4;
  }
  else {
    BVar4 = StartServiceW(param_2,param_3,param_4);
    if (BVar4 != 0) {
      *param_1 = 0;
      param_1[1] = 0;
      param_1[2] = 0;
      param_1[3] = 0;
      param_1[4] = 0;
      param_1[5] = 0;
      param_1[6] = 0;
      *(undefined1 *)(param_1 + 6) = 0;
      goto LAB_14002ae2a;
    }
    DVar5 = GetLastError();
    local_4c0 = 0;
    local_4b0 = 0;
    uStack_4a8 = 0xf;
    FUN_1400106a0(&local_4c0,(undefined8 *)"StartServiceW failed",0x14);
    local_498 = DVar5;
  }
  ppuStack_490 = &PTR_vftable_14007ad08;
  *param_1 = CONCAT44(uStack_494,local_498);
  param_1[1] = &PTR_vftable_14007ad08;
  param_1[2] = local_4c0;
  param_1[3] = uStack_4b8;
  param_1[4] = local_4b0;
  param_1[5] = uStack_4a8;
  *(undefined1 *)(param_1 + 6) = 1;
LAB_14002ae2a:
  FUN_140015270((longlong)&local_468);
  FUN_14002f160(local_48 ^ (ulonglong)auStackY_518);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_14002ae60 @ 14002ae60