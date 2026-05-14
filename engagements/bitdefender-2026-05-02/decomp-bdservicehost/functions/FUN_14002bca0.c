void FUN_14002bca0(undefined8 *param_1,LPCWSTR param_2)

{
  int iVar1;
  int iVar2;
  DWORD DVar3;
  SC_HANDLE pSVar4;
  undefined1 auStackY_538 [32];
  HMODULE *local_4f8;
  int local_4f0;
  undefined4 local_4e8 [2];
  undefined8 local_4e0;
  undefined4 uStack_4d8;
  undefined4 uStack_4d4;
  undefined8 local_4d0;
  undefined8 uStack_4c8;
  undefined8 *local_4c0;
  undefined8 local_4b8;
  undefined8 uStack_4b0;
  undefined8 local_4a8;
  DWORD local_4a0;
  undefined4 uStack_49c;
  undefined **ppuStack_498;
  undefined8 local_470;
  char local_468;
  SC_HANDLE local_460;
  char local_458;
  DWORD local_448;
  wchar_t local_444 [260];
  wchar_t local_23c [266];
  ulonglong local_28;
  
  local_28 = DAT_14007a060 ^ (ulonglong)auStackY_538;
  local_4c0 = param_1;
  local_448 = timeGetTime();
  wcsncpy_s(local_444,0x102,L"set_service_launch_type",0xffffffffffffffff);
  wcscat_s(local_444,0x104,L"()");
  wcsncpy_s(local_23c,0x104,L"set_service_launch_type",0xffffffffffffffff);
  if (DAT_14007d500 + DAT_14007d504 != 0) {
    local_4f8 = FUN_14000eb20();
    LOCK();
    local_4f0 = 1;
    UNLOCK();
    if (local_4f8 == (HMODULE *)0x0) {
      local_4f8 = FUN_14000eb20();
      LOCK();
      local_4f0 = 2;
      UNLOCK();
    }
    local_4e8[0] = 0x20;
    FUN_1400019c0((longlong)local_4f8,1,local_4e8,&IMAGE_DOS_HEADER_140000000,local_23c,L"-> %s");
    LOCK();
    UNLOCK();
    iVar1 = local_4f0 + -1;
    iVar2 = local_4f0;
    while (-1 < iVar1) {
      local_4f0 = iVar2 + -1;
      FUN_140011e70();
      LOCK();
      UNLOCK();
      iVar1 = iVar2 + -2;
      iVar2 = local_4f0;
    }
    LOCK();
    UNLOCK();
  }
  pSVar4 = OpenSCManagerW((LPCWSTR)0x0,(LPCWSTR)0x0,0xf003f);
  local_468 = pSVar4 == (SC_HANDLE)0x0;
  if ((bool)local_468) {
    DVar3 = GetLastError();
    local_470 = (SC_HANDLE)CONCAT44(local_470._4_4_,DVar3);
    if (!(bool)local_468) {
      local_4b8 = 0;
      uStack_4b0 = 0;
      local_4a8 = 0;
      FUN_14000ec80(&local_4b8);
                    /* WARNING: Subroutine does not return */
      _CxxThrowException(&local_4b8,(ThrowInfo *)&DAT_1400777e0);
    }
    local_4e0 = 0;
    local_4d0 = 0;
    uStack_4c8 = 0xf;
    FUN_1400106a0(&local_4e0,(undefined8 *)"open_sc_manager failed",0x16);
    ppuStack_498 = &PTR_vftable_14007ad08;
    *param_1 = CONCAT44(uStack_49c,DVar3);
    param_1[1] = &PTR_vftable_14007ad08;
    *(undefined4 *)(param_1 + 2) = (undefined4)local_4e0;
    *(undefined4 *)((longlong)param_1 + 0x14) = local_4e0._4_4_;
    *(undefined4 *)(param_1 + 3) = uStack_4d8;
    *(undefined4 *)((longlong)param_1 + 0x1c) = uStack_4d4;
    param_1[4] = local_4d0;
    param_1[5] = uStack_4c8;
    *(undefined1 *)(param_1 + 6) = 1;
    local_4a0 = DVar3;
  }
  else {
    local_470 = pSVar4;
    pSVar4 = OpenServiceW(pSVar4,param_2,2);
    local_458 = pSVar4 == (SC_HANDLE)0x0;
    if ((bool)local_458) {
      DVar3 = GetLastError();
      local_460 = (SC_HANDLE)CONCAT44(local_460._4_4_,DVar3);
      if (!(bool)local_458) {
        local_4b8 = 0;
        uStack_4b0 = 0;
        local_4a8 = 0;
        FUN_14000ec80(&local_4b8);
                    /* WARNING: Subroutine does not return */
        _CxxThrowException(&local_4b8,(ThrowInfo *)&DAT_1400777e0);
      }
      local_4e0 = 0;
      local_4d0 = 0;
      uStack_4c8 = 0xf;
      FUN_1400106a0(&local_4e0,(undefined8 *)"open_service failed",0x13);
      ppuStack_498 = &PTR_vftable_14007ad08;
      *param_1 = CONCAT44(uStack_49c,DVar3);
      param_1[1] = &PTR_vftable_14007ad08;
      *(undefined4 *)(param_1 + 2) = (undefined4)local_4e0;
      *(undefined4 *)((longlong)param_1 + 0x14) = local_4e0._4_4_;
      *(undefined4 *)(param_1 + 3) = uStack_4d8;
      *(undefined4 *)((longlong)param_1 + 0x1c) = uStack_4d4;
      param_1[4] = local_4d0;
      param_1[5] = uStack_4c8;
      *(undefined1 *)(param_1 + 6) = 1;
      local_4a0 = DVar3;
    }
    else {
      local_460 = pSVar4;
      FUN_14002bba0(param_1,pSVar4,0);
    }
    if (((local_458 != -1) && (local_458 == '\0')) && (local_460 != (SC_HANDLE)0x0)) {
      CloseServiceHandle(local_460);
    }
  }
  if (((local_468 != -1) && (local_468 == '\0')) && (local_470 != (SC_HANDLE)0x0)) {
    CloseServiceHandle(local_470);
  }
  FUN_140015270((longlong)&local_448);
  FUN_14002f160(local_28 ^ (ulonglong)auStackY_538);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_14002c000 @ 14002c000