void FUN_140017910(undefined8 param_1)

{
  HMODULE pHVar1;
  int iVar2;
  HMODULE hModule;
  FARPROC pFVar3;
  longlong lVar4;
  undefined8 *puVar5;
  longlong *plVar6;
  longlong lVar7;
  LPCWSTR lpLibFileName;
  undefined1 auStackY_108 [32];
  int local_c8;
  undefined4 local_c4;
  HMODULE *local_c0;
  int local_b8;
  HMODULE *local_b0;
  int local_a8;
  HMODULE *local_a0;
  int local_98;
  DWORD local_88;
  undefined4 uStack_84;
  undefined **ppuStack_80;
  undefined4 local_68;
  undefined4 local_64;
  undefined4 local_60 [2];
  undefined8 local_58;
  HMODULE local_50;
  DWORD local_48;
  undefined4 uStack_44;
  undefined **ppuStack_40;
  ulonglong local_38;
  
  local_38 = DAT_14007a060 ^ (ulonglong)auStackY_108;
  local_c8 = 0;
  local_c8._0_1_ = '\0';
  uStack_44 = 0;
  ppuStack_40 = &PTR_vftable_14007ac70;
  local_50 = (HMODULE)0x0;
  if ((DAT_14007acf0 == 0) || (*(longlong *)(DAT_14007acf0 + 0x90) == 0)) {
    iVar2 = FUN_14000eb10();
    if (iVar2 != 0) {
      plVar6 = FUN_14000eae0((undefined8 *)&local_88);
      lVar7 = FUN_14000ea70(plVar6);
      local_c4 = 4;
      FUN_1400019c0(lVar7,0,&local_c4,&IMAGE_DOS_HEADER_140000000,
                    L"service_additional_configuration::install",
                    L"Global service configuration is null or the relative dll path is empty. This is an error."
                   );
      FUN_14000eaa0((undefined8 *)&local_88);
    }
    FUN_140001ab0((undefined8 *)&local_88,0x14006bf08);
                    /* WARNING: Subroutine does not return */
    _CxxThrowException(&local_88,(ThrowInfo *)&DAT_140077818);
  }
  lpLibFileName = (LPCWSTR)(DAT_14007acf0 + 0x80);
  if (7 < *(ulonglong *)(DAT_14007acf0 + 0x98)) {
    lpLibFileName = *(LPCWSTR *)lpLibFileName;
  }
  hModule = LoadLibraryW(lpLibFileName);
  pHVar1 = hModule;
  if (hModule == (HMODULE)0x0) {
    local_88 = GetLastError();
    ppuStack_80 = &PTR_vftable_14007ad08;
    uStack_44 = uStack_84;
    ppuStack_40 = &PTR_vftable_14007ad08;
    local_50 = (HMODULE)0x0;
    if (local_88 != 0) {
      local_48 = local_88;
      iVar2 = FUN_14000eb10();
      if (iVar2 != 0) {
        plVar6 = FUN_14000eae0((undefined8 *)&local_88);
        lVar7 = FUN_14000ea70(plVar6);
        lVar4 = FUN_14000d630(&DAT_14007acf0);
        puVar5 = (undefined8 *)FUN_14001b440(lVar4);
        FUN_14000e4a0(puVar5);
        local_c4 = 4;
        FUN_1400019c0(lVar7,0,&local_c4,&IMAGE_DOS_HEADER_140000000,
                      L"service_additional_configuration::install",L"Can\'t load service dll %s");
        FUN_14000eaa0((undefined8 *)&local_88);
      }
      FUN_140001ab0((undefined8 *)&local_88,0x14006b950);
                    /* WARNING: Subroutine does not return */
      _CxxThrowException(&local_88,(ThrowInfo *)&DAT_140077818);
    }
    local_88 = 0;
    pHVar1 = local_50;
  }
  local_50 = pHVar1;
  local_48 = 0;
  pFVar3 = GetProcAddress(hModule,"SvcGetObject");
  if (pFVar3 == (FARPROC)0x0) {
    if (DAT_14007d500 + DAT_14007d504 != 0) {
      local_b8 = 0;
      local_c0 = FUN_14000eb20();
      LOCK();
      local_b8 = local_b8 + 1;
      UNLOCK();
      local_c8 = 4;
      if (local_c0 == (HMODULE *)0x0) {
        local_c0 = FUN_14000eb20();
        LOCK();
        local_b8 = local_b8 + 1;
        UNLOCK();
      }
      local_68 = 0x10;
      FUN_1400019c0((longlong)local_c0,0,&local_68,&IMAGE_DOS_HEADER_140000000,
                    L"service_additional_configuration::install",
                    L"SvcGetObject is not exported. This is not an error.");
    }
    if (local_c8 != 0) {
      local_c0 = (HMODULE *)0x0;
      LOCK();
      UNLOCK();
      iVar2 = local_b8;
      while (local_b8 = iVar2 + -1, -1 < iVar2 + -1) {
        FUN_140011e70();
        LOCK();
        UNLOCK();
        iVar2 = local_b8;
      }
      LOCK();
      UNLOCK();
      local_b8 = iVar2;
    }
  }
  else {
    GetProcAddress(hModule,"SvcReleaseObject");
    local_58 = 0;
    iVar2 = (*(code *)PTR__guard_dispatch_icall_14005b538)
                      ("IServiceAdditionalConfiguration.1",&local_58);
    if (iVar2 == 0) {
      puVar5 = &DAT_14007acd0;
      if (7 < DAT_14007ace8) {
        puVar5 = DAT_14007acd0;
      }
      iVar2 = (*(code *)PTR__guard_dispatch_icall_14005b538)(local_58,puVar5,param_1);
      (*(code *)PTR__guard_dispatch_icall_14005b538)("IServiceAdditionalConfiguration.1",&local_58);
      if (iVar2 < 0) {
        iVar2 = FUN_14000eb10();
        if (iVar2 != 0) {
          plVar6 = FUN_14000eae0((undefined8 *)&local_88);
          lVar7 = FUN_14000ea70(plVar6);
          local_c4 = 4;
          FUN_1400019c0(lVar7,0,&local_c4,&IMAGE_DOS_HEADER_140000000,
                        L"service_additional_configuration::install",
                        L"IServiceAdditionalConfiguration::Install failed with code %d.");
          FUN_14000eaa0((undefined8 *)&local_88);
        }
        FUN_140001ab0((undefined8 *)&local_88,0x14006c1c0);
                    /* WARNING: Subroutine does not return */
        _CxxThrowException(&local_88,(ThrowInfo *)&DAT_140077818);
      }
      if (DAT_14007d500 + DAT_14007d504 != 0) {
        local_98 = 0;
        local_a0 = FUN_14000eb20();
        LOCK();
        local_98 = local_98 + 1;
        UNLOCK();
        local_c8._0_1_ = -0x80;
        if (local_a0 == (HMODULE *)0x0) {
          local_a0 = FUN_14000eb20();
          LOCK();
          local_98 = local_98 + 1;
          UNLOCK();
        }
        local_60[0] = 0x10;
        FUN_1400019c0((longlong)local_a0,0,local_60,&IMAGE_DOS_HEADER_140000000,
                      L"service_additional_configuration::install",
                      L"IServiceAdditionalConfiguration::Install completed with success. Code: %d.")
        ;
      }
      if ((char)local_c8 < '\0') {
        local_a0 = (HMODULE *)0x0;
        LOCK();
        UNLOCK();
        iVar2 = local_98;
        while (local_98 = iVar2 + -1, -1 < iVar2 + -1) {
          FUN_140011e70();
          LOCK();
          UNLOCK();
          iVar2 = local_98;
        }
        LOCK();
        UNLOCK();
        local_98 = iVar2;
      }
    }
    else {
      if (iVar2 != 2) {
        iVar2 = FUN_14000eb10();
        if (iVar2 != 0) {
          plVar6 = FUN_14000eae0((undefined8 *)&local_88);
          lVar7 = FUN_14000ea70(plVar6);
          FUN_140017900();
          local_c4 = 4;
          FUN_1400019c0(lVar7,0,&local_c4,&IMAGE_DOS_HEADER_140000000,
                        L"service_additional_configuration::install",
                        L"SvcGetObject cannot create object %hs although it supports the interface. This is an error."
                       );
          FUN_14000eaa0((undefined8 *)&local_88);
        }
        FUN_140001ab0((undefined8 *)&local_88,0x14006c108);
                    /* WARNING: Subroutine does not return */
        _CxxThrowException(&local_88,(ThrowInfo *)&DAT_140077818);
      }
      if (DAT_14007d500 + DAT_14007d504 != 0) {
        local_a8 = 0;
        local_b0 = FUN_14000eb20();
        LOCK();
        local_a8 = local_a8 + 1;
        UNLOCK();
        local_c8 = 0x10;
        if (local_b0 == (HMODULE *)0x0) {
          local_b0 = FUN_14000eb20();
          LOCK();
          local_a8 = local_a8 + 1;
          UNLOCK();
        }
        local_64 = 0x10;
        FUN_1400019c0((longlong)local_b0,0,&local_64,&IMAGE_DOS_HEADER_140000000,
                      L"service_additional_configuration::install",
                      L"The interface %hs is not supported.");
      }
      if (local_c8 != 0) {
        local_b0 = (HMODULE *)0x0;
        LOCK();
        UNLOCK();
        iVar2 = local_a8;
        while (local_a8 = iVar2 + -1, -1 < iVar2 + -1) {
          FUN_140011e70();
          LOCK();
          UNLOCK();
          iVar2 = local_a8;
        }
        LOCK();
        UNLOCK();
        local_a8 = iVar2;
      }
    }
  }
  if (hModule != (HMODULE)0x0) {
    FreeLibrary(hModule);
  }
  FUN_14002f160(local_38 ^ (ulonglong)auStackY_108);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_140017f40 @ 140017f40