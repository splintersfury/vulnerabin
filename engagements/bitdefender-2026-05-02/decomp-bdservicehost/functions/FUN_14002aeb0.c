void FUN_14002aeb0(undefined8 *param_1,LPCWSTR param_2,undefined8 param_3,DWORD param_4,
                  LPCWSTR *param_5)

{
  int iVar1;
  int iVar2;
  char cVar3;
  DWORD DVar4;
  SC_HANDLE pSVar5;
  undefined8 *puVar6;
  SC_HANDLE pSVar7;
  bool bVar8;
  undefined1 auStackY_5b8 [32];
  HMODULE *local_578;
  int local_570;
  undefined4 local_568 [2];
  undefined8 *local_560;
  undefined8 local_558;
  undefined4 uStack_550;
  undefined4 uStack_54c;
  undefined8 local_548;
  undefined8 uStack_540;
  undefined8 local_528;
  undefined **ppuStack_520;
  longlong local_518;
  undefined8 local_508;
  undefined8 uStack_500;
  DWORD local_4f8;
  undefined4 uStack_4f4;
  undefined **ppuStack_4f0;
  undefined8 local_4c8;
  char local_4c0;
  SC_HANDLE local_4b8;
  char local_4b0;
  undefined8 local_4a8 [6];
  char local_478;
  DWORD local_468;
  wchar_t local_464 [260];
  wchar_t local_25c [266];
  ulonglong local_48;
  
  local_48 = DAT_14007a060 ^ (ulonglong)auStackY_5b8;
  local_560 = param_1;
  local_468 = timeGetTime();
  wcsncpy_s(local_464,0x102,L"start_service",0xffffffffffffffff);
  wcscat_s(local_464,0x104,L"()");
  wcsncpy_s(local_25c,0x104,L"start_service",0xffffffffffffffff);
  if (DAT_14007d500 + DAT_14007d504 != 0) {
    local_578 = FUN_14000eb20();
    LOCK();
    local_570 = 1;
    UNLOCK();
    if (local_578 == (HMODULE *)0x0) {
      local_578 = FUN_14000eb20();
      LOCK();
      local_570 = 2;
      UNLOCK();
    }
    local_568[0] = 0x20;
    FUN_1400019c0((longlong)local_578,1,local_568,&IMAGE_DOS_HEADER_140000000,local_25c,L"-> %s");
    LOCK();
    UNLOCK();
    iVar1 = local_570 + -1;
    iVar2 = local_570;
    while (-1 < iVar1) {
      local_570 = iVar2 + -1;
      FUN_140011e70();
      LOCK();
      UNLOCK();
      iVar1 = iVar2 + -2;
      iVar2 = local_570;
    }
    LOCK();
    UNLOCK();
  }
  pSVar5 = OpenSCManagerW((LPCWSTR)0x0,(LPCWSTR)0x0,0xf003f);
  local_4c0 = pSVar5 == (SC_HANDLE)0x0;
  if ((bool)local_4c0) {
    DVar4 = GetLastError();
    local_4c8 = (SC_HANDLE)CONCAT44(local_4c8._4_4_,DVar4);
    if (!(bool)local_4c0) {
      local_528 = 0;
      ppuStack_520 = (undefined **)0x0;
      local_518 = 0;
      FUN_14000ec80(&local_528);
                    /* WARNING: Subroutine does not return */
      _CxxThrowException(&local_528,(ThrowInfo *)&DAT_1400777e0);
    }
    local_558 = 0;
    local_548 = 0;
    uStack_540 = 0xf;
    FUN_1400106a0(&local_558,(undefined8 *)"open_sc_manager failed",0x16);
    ppuStack_4f0 = &PTR_vftable_14007ad08;
    *param_1 = CONCAT44(uStack_4f4,DVar4);
    param_1[1] = &PTR_vftable_14007ad08;
    *(undefined4 *)(param_1 + 2) = (undefined4)local_558;
    *(undefined4 *)((longlong)param_1 + 0x14) = local_558._4_4_;
    *(undefined4 *)(param_1 + 3) = uStack_550;
    *(undefined4 *)((longlong)param_1 + 0x1c) = uStack_54c;
    param_1[4] = local_548;
    param_1[5] = uStack_540;
    *(undefined1 *)(param_1 + 6) = 1;
    local_4f8 = DVar4;
  }
  else {
    local_4c8 = pSVar5;
    pSVar5 = OpenServiceW(pSVar5,param_2,0x14);
    bVar8 = pSVar5 == (SC_HANDLE)0x0;
    local_4b0 = bVar8;
    if (!bVar8) {
      local_4b8 = pSVar5;
      cVar3 = FUN_14002c1f0(pSVar5,10000);
      if (cVar3 == '\0') {
        local_558 = 0;
        local_548 = 0;
        uStack_540 = 0xf;
        FUN_1400106a0(&local_558,(undefined8 *)"wait_service_to_stop failed",0x1b);
        local_528 = CONCAT44(local_528._4_4_,0x5b4);
        ppuStack_520 = &PTR_vftable_14007ad08;
        local_518 = local_558;
        local_508 = local_548;
        uStack_500 = uStack_540;
        puVar6 = FUN_14002d390((undefined8 *)&local_4f8,&local_528);
        FUN_14002d3d0(param_1,puVar6);
        FUN_14002aba0((longlong)&local_4f8);
        FUN_14002aba0((longlong)&local_528);
      }
      else {
        pSVar7 = pSVar5;
        FUN_14002ac10(local_4a8,pSVar5,param_4,param_5);
        if (local_478 == '\0') {
          cVar3 = FUN_14002c000(pSVar5);
          if (cVar3 == '\0') {
            puVar6 = (undefined8 *)
                     FUN_14002d280((undefined4 *)&local_528,pSVar7,
                                   (undefined8 *)"wait_service_to_start failed");
            puVar6 = FUN_14002d390(&local_558,puVar6);
            FUN_14002d3d0(param_1,puVar6);
            FUN_14002aba0((longlong)&local_558);
            FUN_14002aba0((longlong)&local_528);
          }
          else {
            *param_1 = 0;
            param_1[1] = 0;
            param_1[2] = 0;
            param_1[3] = 0;
            param_1[4] = 0;
            param_1[5] = 0;
            param_1[6] = 0;
            *(undefined1 *)(param_1 + 6) = 0;
          }
        }
        else {
          FUN_14002ae60(param_1,local_4a8);
        }
        FUN_14002d150((longlong)local_4a8);
      }
      FUN_14002a7e0(&local_4b8);
      FUN_14002a7e0(&local_4c8);
      goto LAB_14002b2cd;
    }
    DVar4 = GetLastError();
    local_4b8 = (SC_HANDLE)CONCAT44(local_4b8._4_4_,DVar4);
    if (!bVar8) {
      local_528 = 0;
      ppuStack_520 = (undefined **)0x0;
      local_518 = 0;
      FUN_14000ec80(&local_528);
                    /* WARNING: Subroutine does not return */
      _CxxThrowException(&local_528,(ThrowInfo *)&DAT_1400777e0);
    }
    local_558 = 0;
    local_548 = 0;
    uStack_540 = 0xf;
    FUN_1400106a0(&local_558,(undefined8 *)"open_service failed",0x13);
    ppuStack_4f0 = &PTR_vftable_14007ad08;
    *param_1 = CONCAT44(uStack_4f4,DVar4);
    param_1[1] = &PTR_vftable_14007ad08;
    *(undefined4 *)(param_1 + 2) = (undefined4)local_558;
    *(undefined4 *)((longlong)param_1 + 0x14) = local_558._4_4_;
    *(undefined4 *)(param_1 + 3) = uStack_550;
    *(undefined4 *)((longlong)param_1 + 0x1c) = uStack_54c;
    *(undefined4 *)(param_1 + 4) = (undefined4)local_548;
    *(undefined4 *)((longlong)param_1 + 0x24) = local_548._4_4_;
    *(undefined4 *)(param_1 + 5) = (undefined4)uStack_540;
    *(undefined4 *)((longlong)param_1 + 0x2c) = uStack_540._4_4_;
    *(undefined1 *)(param_1 + 6) = 1;
    local_4f8 = DVar4;
    if (((local_4b0 != -1) && (local_4b0 == '\0')) && (local_4b8 != (SC_HANDLE)0x0)) {
      CloseServiceHandle(local_4b8);
    }
  }
  if (((local_4c0 != -1) && (local_4c0 == '\0')) && (local_4c8 != (SC_HANDLE)0x0)) {
    CloseServiceHandle(local_4c8);
  }
LAB_14002b2cd:
  FUN_140015270((longlong)&local_468);
  FUN_14002f160(local_48 ^ (ulonglong)auStackY_5b8);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_14002b350 @ 14002b350

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */