void FUN_14000c090(void)

{
  code *pcVar1;
  ulonglong uVar2;
  LPCWSTR pWVar3;
  char cVar4;
  BOOL BVar5;
  int iVar6;
  LSTATUS LVar7;
  HMODULE hModule;
  FARPROC pFVar8;
  ulonglong *puVar9;
  undefined8 uVar10;
  LPWSTR pWVar11;
  undefined1 (*pauVar12) [16];
  LPCWSTR pWVar13;
  undefined1 (*pauVar14) [16];
  uint *puVar15;
  undefined8 *puVar16;
  longlong *plVar17;
  undefined1 (*pauVar18) [16];
  wchar_t *pwVar19;
  LPCWSTR ***lpSubKey;
  ulonglong uVar20;
  undefined8 uVar21;
  wchar_t *pwVar22;
  IMAGE_DOS_HEADER *pIVar23;
  LPWSTR *hMem;
  ulonglong uVar24;
  LPWSTR pWVar25;
  bool bVar26;
  bool bVar27;
  undefined1 auStackY_9b8 [32];
  char local_950 [8];
  HMODULE local_948;
  HMODULE *local_940;
  int local_938;
  HMODULE *local_930;
  int local_928;
  undefined4 local_920;
  undefined4 local_91c;
  ulonglong local_918 [2];
  undefined8 local_908;
  ulonglong local_900;
  longlong local_8f8 [2];
  undefined8 local_8e8;
  ulonglong local_8e0;
  undefined8 local_8d8;
  undefined1 (*local_8d0) [16];
  undefined8 local_8c0 [3];
  undefined8 local_8a8 [3];
  undefined8 local_890 [3];
  longlong local_878 [5];
  undefined8 local_850 [5];
  longlong local_828 [16];
  char local_7a8;
  longlong local_730 [16];
  char local_6b0;
  longlong local_638 [16];
  char local_5b8;
  longlong local_540 [16];
  char local_4c0;
  char *local_350;
  BOOL local_348;
  _SID_IDENTIFIER_AUTHORITY local_344;
  int local_33c;
  ulonglong local_338;
  ulonglong uStack_330;
  ulonglong local_328;
  ulonglong uStack_320;
  char local_318;
  LPWSTR *local_310;
  ulonglong uStack_308;
  LPCWSTR **local_300 [2];
  undefined8 local_2f0;
  ulonglong local_2e8;
  undefined8 local_2e0 [6];
  char local_2b0;
  undefined4 local_2a8;
  undefined4 local_2a4;
  undefined **local_2a0;
  wchar_t *local_298;
  wchar_t *local_290;
  undefined8 *local_288;
  undefined **local_280;
  undefined8 local_278;
  undefined8 local_270;
  undefined8 local_268;
  undefined2 local_260;
  undefined4 local_258;
  undefined ***local_254;
  undefined4 local_24c;
  wchar_t local_248 [261];
  undefined4 local_3e;
  undefined1 (*local_38) [16];
  undefined **ppuStack_30;
  ulonglong local_28;
  
  local_28 = DAT_14007a060 ^ (ulonglong)auStackY_9b8;
  uVar24 = 0;
  bVar26 = false;
  local_318 = '\0';
  local_350 = "dll_dirs-{F67BB3AD-7B5E-4C2D-A22B-747BC163AB78}";
  hModule = GetModuleHandleW(L"kernel32.dll");
  if ((hModule != (HMODULE)0x0) &&
     (pFVar8 = GetProcAddress(hModule,"SetDefaultDllDirectories"), pFVar8 != (FARPROC)0x0)) {
    (*(code *)PTR__guard_dispatch_icall_14005b538)(0x1000);
  }
  puVar9 = (ulonglong *)FUN_140009c70((undefined4 *)local_878);
  if ((char)puVar9[4] == '\0') {
    if (local_318 != '\0') {
      if (7 < uStack_320) {
        if ((0xfff < uStack_320 * 2 + 2) && (0x1f < (local_338 - *(longlong *)(local_338 - 8)) - 8))
        {
          FUN_140035d28();
LAB_14000d0d4:
          FUN_140035d28();
          goto LAB_14000d0da;
        }
        FUN_14002f180();
      }
      local_328 = 0;
      uStack_320 = 7;
      local_338 = local_338 & 0xffffffffffff0000;
      local_318 = '\0';
    }
  }
  else if (local_318 == '\0') {
    local_338 = *puVar9;
    uStack_330 = puVar9[1];
    local_328 = puVar9[2];
    uStack_320 = puVar9[3];
    puVar9[2] = 0;
    puVar9[3] = 7;
    *(undefined2 *)puVar9 = 0;
    local_318 = '\x01';
  }
  else {
    FUN_14000e6b0((longlong *)&local_338,(longlong *)puVar9);
  }
  FUN_14000d470(local_878);
  local_348 = 0;
  local_344.Value[0] = '\0';
  local_344.Value[1] = '\0';
  local_344.Value[2] = '\0';
  local_344.Value[3] = '\0';
  local_344.Value[4] = '\0';
  local_344.Value[5] = '\x05';
  local_350 = (char *)0x0;
  pIVar23 = (IMAGE_DOS_HEADER *)0x220;
  BVar5 = AllocateAndInitializeSid(&local_344,'\x02',0x20,0x220,0,0,0,0,0,0,&local_350);
  if (BVar5 != 0) {
    BVar5 = CheckTokenMembership((HANDLE)0x0,local_350,&local_348);
    if (BVar5 == 0) {
      local_348 = 0;
    }
    FreeSid(local_350);
  }
  if (local_348 == 1) {
    pwVar19 = (wchar_t *)0x0;
    uVar21 = 0x260;
    FUN_140031e00((undefined1 (*) [16])&local_298,0,0x260);
    local_288 = &local_278;
    local_280 = &PTR_vftable_14007aca0;
    local_260 = 0;
    local_258 = 0xabcd;
    local_24c = 0xabcd;
    local_254 = &local_280;
    local_3e = 0xabcd;
    local_298 = local_248;
    local_270 = 0x104;
    local_268 = 0x104;
    local_290 = local_248;
    local_278 = 0;
    local_248[0] = L'\0';
    uVar10 = FUN_14000d240((longlong *)&local_298);
    if ((int)uVar10 != 0) {
      pwVar19 = L"";
      if (local_298 != (wchar_t *)0x0) {
        pwVar19 = local_298;
      }
      FID_conflict__putenv_s(L"OPENSSL_CONF",pwVar19);
      pwVar19 = L"";
      if (local_298 != (wchar_t *)0x0) {
        pwVar19 = local_298;
      }
      FID_conflict__putenv_s(L"OPENSSL_WIN32_UTF8",pwVar19);
    }
    FUN_140012980((longlong *)&local_298);
    FUN_14000b750();
    FUN_140006b60(local_950,pwVar19,uVar21);
    local_310 = (LPWSTR *)0x0;
    uStack_308 = 0;
    local_33c = 0;
    pWVar11 = GetCommandLineW();
    local_310 = CommandLineToArgvW(pWVar11,&local_33c);
    uStack_308 = (ulonglong)local_33c;
    if (DAT_14007d500 + DAT_14007d504 != 0) {
      local_938 = 0;
      local_940 = FUN_14000eb20();
      LOCK();
      local_938 = local_938 + 1;
      UNLOCK();
      bVar26 = true;
      if (local_940 == (HMODULE *)0x0) {
        local_940 = FUN_14000eb20();
        LOCK();
        local_938 = local_938 + 1;
        UNLOCK();
      }
      local_920 = 0x10;
      pIVar23 = &IMAGE_DOS_HEADER_140000000;
      FUN_1400019c0((longlong)local_940,0,&local_920,&IMAGE_DOS_HEADER_140000000,L"wWinMain",
                    L"First log");
    }
    uVar20 = 0xffffffffffffffff;
    if (bVar26) {
      local_940 = (HMODULE *)0x0;
      LOCK();
      UNLOCK();
      iVar6 = local_938;
      while (local_938 = iVar6 + -1, -1 < iVar6 + -1) {
        FUN_140011e70();
        LOCK();
        UNLOCK();
        iVar6 = local_938;
      }
      LOCK();
      UNLOCK();
      local_938 = iVar6;
    }
    FUN_140002e10(local_828,0x10,0x14006b360);
    uVar2 = uStack_308;
    hMem = local_310;
    if (local_7a8 != '\0') {
      FUN_140012a30(local_828,0x14006b378);
      uVar2 = uStack_308;
      hMem = local_310;
    }
    for (; uVar24 != uVar2; uVar24 = uVar24 + 1) {
      if ((hMem == (LPWSTR *)0x0) || (uVar2 <= uVar24)) goto LAB_14000d0d4;
      if ((local_7a8 != '\0') &&
         (FUN_140012a30(local_828,(longlong)hMem[uVar24]), local_7a8 != '\0')) {
        FUN_1400144b0(local_828,&DAT_14006b340);
      }
    }
    FUN_140003090(local_828);
    if (uVar2 < 2) {
      FUN_140002e10(local_730,4,0x14006b360);
      if (local_6b0 != '\0') {
        FUN_140012a30(local_730,0x14006b3a8);
      }
      FUN_140003090(local_730);
      if (hMem != (LPWSTR *)0x0) {
        LocalFree(hMem);
      }
      if (((local_950[0] == '\0') || (local_948 != (HMODULE)0x0)) &&
         (FUN_140011e70(), local_948 != (HMODULE)0x0)) {
        FreeLibrary(local_948);
        local_948 = (HMODULE)0x0;
      }
      FUN_14000d470((longlong *)&local_338);
      goto LAB_14000d09c;
    }
    cVar4 = FUN_14000b390();
    if (cVar4 != '\0') {
      pWVar11 = hMem[1];
      pWVar25 = pWVar11 + 1;
      if (*pWVar11 != L'/') {
        pWVar25 = pWVar11;
      }
      uVar24 = 0xffffffffffffffff;
      do {
        uVar24 = uVar24 + 1;
      } while (pWVar25[uVar24] != L'\0');
      FUN_140010340(&DAT_14007acb0,(undefined8 *)pWVar25,uVar24);
      pwVar22 = L"wWinMain";
      pwVar19 = (LPWSTR)0x10;
      FUN_140002e10(local_638,0x10,0x14006b360);
      if (local_5b8 != '\0') {
        pwVar19 = L"config path: ";
        FUN_140012a30(local_638,0x14006b3d8);
        if (local_5b8 != '\0') {
          pwVar19 = pWVar25;
          FUN_140012a30(local_638,(longlong)pWVar25);
        }
      }
      plVar17 = local_638;
      FUN_140003090(plVar17);
      if (uVar2 == 2) {
        cVar4 = FUN_14000bfe0(plVar17,pwVar19,pwVar22);
        if (cVar4 == '\0') {
          pauVar12 = (undefined1 (*) [16])operator_new(0xf0);
          local_38 = pauVar12;
          FUN_140031e00(pauVar12,0,0xf0);
          local_8e8 = 0;
          local_8e0 = 7;
          local_8f8[0] = 0;
          do {
            uVar20 = uVar20 + 1;
          } while (pWVar25[uVar20] != L'\0');
          FUN_140010340(local_8f8,(undefined8 *)pWVar25,uVar20);
          pWVar13 = (LPCWSTR)FUN_14001b1c0((longlong *)pauVar12,(wchar_t *)local_8f8,uVar20,
                                           (LPCSTR ***)pIVar23);
          if (7 < local_8e0) {
            if ((0xfff < local_8e0 * 2 + 2) &&
               (0x1f < (local_8f8[0] - *(longlong *)(local_8f8[0] + -8)) - 8U)) {
LAB_14000d0da:
              FUN_140035d28();
              pcVar1 = (code *)swi(3);
              (*pcVar1)();
              return;
            }
            FUN_14002f180();
          }
          pWVar3 = DAT_14007acf0;
          bVar26 = DAT_14007acf0 != (LPCWSTR)0x0;
          DAT_14007acf0 = pWVar13;
          if (bVar26) {
            FUN_1400108b0((longlong *)pWVar3);
            FUN_14002f180();
          }
          FUN_14000baf0();
          FUN_14000b2a0();
          LocalFree(hMem);
          if (((local_950[0] == '\0') || (local_948 != (HMODULE)0x0)) &&
             (FUN_140011e70(), local_948 != (HMODULE)0x0)) {
            FreeLibrary(local_948);
            local_948 = (HMODULE)0x0;
          }
          FUN_14000d470((longlong *)&local_338);
        }
        else {
          LocalFree(hMem);
          if (((local_950[0] == '\0') || (local_948 != (HMODULE)0x0)) &&
             (FUN_140011e70(), local_948 != (HMODULE)0x0)) {
            FreeLibrary(local_948);
            local_948 = (HMODULE)0x0;
          }
          FUN_14000d470((longlong *)&local_338);
        }
        goto LAB_14000d09c;
      }
      pauVar12 = (undefined1 (*) [16])operator_new(0xf0);
      local_8d0 = pauVar12;
      FUN_140031e00(pauVar12,0,0xf0);
      local_908 = 0;
      local_900 = 7;
      local_918[0] = 0;
      uVar24 = 0xffffffffffffffff;
      do {
        uVar24 = uVar24 + 1;
      } while (pWVar25[uVar24] != L'\0');
      FUN_140010340((longlong *)local_918,(undefined8 *)pWVar25,uVar24);
      pWVar13 = (LPCWSTR)FUN_14001b1c0((longlong *)pauVar12,(wchar_t *)local_918,uVar24,
                                       (LPCSTR ***)pIVar23);
      if (7 < local_900) {
        if ((0xfff < local_900 * 2 + 2) &&
           (0x1f < (local_918[0] - *(longlong *)(local_918[0] - 8)) - 8)) {
          FUN_140035d28();
          pcVar1 = (code *)swi(3);
          (*pcVar1)();
          return;
        }
        FUN_14002f180();
      }
      pWVar3 = DAT_14007acf0;
      local_918[0] = local_918[0] & 0xffffffffffff0000;
      local_900 = 7;
      local_908 = 0;
      bVar26 = false;
      bVar27 = DAT_14007acf0 != (LPCWSTR)0x0;
      DAT_14007acf0 = pWVar13;
      if (bVar27) {
        FUN_1400108b0((longlong *)pWVar3);
        FUN_14002f180();
      }
      FUN_14000baf0();
      pauVar12 = (undefined1 (*) [16])hMem[2];
      pauVar18 = (undefined1 (*) [16])((longlong)*pauVar12 + 2);
      if (*(WCHAR *)*pauVar12 != L'/') {
        pauVar18 = pauVar12;
      }
      uVar20 = FUN_140038420((ushort *)pauVar18,(ushort *)L"install");
      if ((int)uVar20 == 0) {
        FUN_14002c690((undefined8 *)pWVar25);
        FUN_140017910(pWVar25);
      }
      else {
        uVar20 = FUN_140038420((ushort *)pauVar18,(ushort *)L"uninstall");
        if ((int)uVar20 == 0) {
          pWVar13 = DAT_14007acf0;
          if (7 < *(ulonglong *)(DAT_14007acf0 + 0xc)) {
            pWVar13 = *(LPCWSTR *)DAT_14007acf0;
          }
          iVar6 = FUN_14002a810(pWVar13);
          if (iVar6 != 0) {
            FUN_140002e10(local_540,0x10,0x14006df30);
            if (local_4c0 != '\0') {
              FUN_140012a30(local_540,0x14006deb0);
            }
            FUN_140003090(local_540);
            local_2f0 = 0;
            local_2e8 = 7;
            local_300[0] = (LPCWSTR **)0x0;
            FUN_140010340((longlong *)local_300,
                          (undefined8 *)L"SYSTEM\\CurrentControlSet\\Services\\",0x22);
            pWVar13 = DAT_14007acf0;
            if (7 < *(ulonglong *)(DAT_14007acf0 + 0xc)) {
              pWVar13 = *(LPCWSTR *)DAT_14007acf0;
            }
            FUN_14000e630(local_300,(undefined8 *)pWVar13,*(ulonglong *)(DAT_14007acf0 + 8));
            lpSubKey = local_300;
            if (7 < local_2e8) {
              lpSubKey = (LPCWSTR ***)local_300[0];
            }
            local_8d8 = 0xffffffff80000002;
            local_2a4 = 0;
            LVar7 = RegDeleteKeyW((HKEY)0xffffffff80000002,(LPCWSTR)lpSubKey);
            if (LVar7 != 0) {
LAB_14000d0ec:
              local_38 = (undefined1 (*) [16])CONCAT44(local_38._4_4_,LVar7);
              ppuStack_30 = &PTR_vftable_14007ad08;
              FUN_140003760(local_850,&local_38,(undefined8 *)"RegDeleteKey failed");
                    /* WARNING: Subroutine does not return */
              _CxxThrowException(local_850,(ThrowInfo *)&DAT_140077a60);
            }
            local_2a8 = 0;
            local_2a0 = &PTR_vftable_14007ac70;
            local_8d8 = 0;
            if (7 < local_2e8) {
              if ((0xfff < local_2e8 * 2 + 2) &&
                 (0x1f < (ulonglong)((longlong)local_300[0] + (-8 - (longlong)local_300[0][-1])))) {
                LVar7 = FUN_140035d28();
                goto LAB_14000d0ec;
              }
              FUN_14002f180();
            }
            local_2f0 = 0;
            local_2e8 = 7;
            local_300[0] = (LPCWSTR **)((ulonglong)local_300[0] & 0xffffffffffff0000);
          }
          if (DAT_14007d500 + DAT_14007d504 != 0) {
            local_928 = 0;
            local_930 = FUN_14000eb20();
            LOCK();
            local_928 = local_928 + 1;
            UNLOCK();
            bVar26 = true;
            if (local_930 == (HMODULE *)0x0) {
              local_930 = FUN_14000eb20();
              LOCK();
              local_928 = local_928 + 1;
              UNLOCK();
            }
            local_91c = 0x10;
            FUN_1400019c0((longlong)local_930,0,&local_91c,&IMAGE_DOS_HEADER_140000000,
                          L"service_additional_configuration::uninstall",
                          L"uninstall does nothing at this time. Returning.");
          }
          hMem = local_310;
          if (bVar26) {
            local_930 = (HMODULE *)0x0;
            LOCK();
            UNLOCK();
            iVar6 = local_928;
            while (local_928 = iVar6 + -1, local_310 = hMem, -1 < iVar6 + -1) {
              FUN_140011e70();
              LOCK();
              UNLOCK();
              hMem = local_310;
              iVar6 = local_928;
            }
            LOCK();
            UNLOCK();
            local_928 = iVar6;
          }
        }
        else {
          uVar20 = FUN_140038420((ushort *)pauVar18,(ushort *)L"enable");
          if ((int)uVar20 == 0) {
            pWVar13 = DAT_14007acf0;
            if (7 < *(ulonglong *)(DAT_14007acf0 + 0xc)) {
              pWVar13 = *(LPCWSTR *)DAT_14007acf0;
            }
            FUN_14002b840(local_2e0,pWVar13);
            if (local_2b0 != '\0') {
              puVar15 = (uint *)FUN_14002d1c0((longlong)local_2e0);
              puVar16 = (undefined8 *)FUN_14002a6a0(local_8f8,puVar15);
              FUN_140001a40(local_8c0,puVar16);
                    /* WARNING: Subroutine does not return */
              _CxxThrowException(local_8c0,(ThrowInfo *)&DAT_140077818);
            }
LAB_14000cffa:
            FUN_14002d150((longlong)local_2e0);
          }
          else {
            uVar20 = FUN_140038420((ushort *)pauVar18,(ushort *)L"disable");
            if ((int)uVar20 == 0) {
              FUN_14002cd20();
            }
            else {
              uVar20 = FUN_140038420((ushort *)pauVar18,(ushort *)L"start");
              if ((int)uVar20 != 0) {
                uVar20 = FUN_140038420((ushort *)pauVar18,(ushort *)L"stop");
                if ((int)uVar20 == 0) {
                  pWVar13 = DAT_14007acf0;
                  if (7 < *(ulonglong *)(DAT_14007acf0 + 0xc)) {
                    pWVar13 = *(LPCWSTR *)DAT_14007acf0;
                  }
                  FUN_14002b4e0(local_2e0,pWVar13);
                  if (local_2b0 != '\0') {
                    puVar15 = (uint *)FUN_14002d1c0((longlong)local_2e0);
                    puVar16 = (undefined8 *)FUN_14002a6a0(local_8f8,puVar15);
                    FUN_140001a40(local_8a8,puVar16);
                    /* WARNING: Subroutine does not return */
                    _CxxThrowException(local_8a8,(ThrowInfo *)&DAT_140077818);
                  }
                }
                else {
                  pwVar19 = L"#crash#";
                  pauVar12 = pauVar18;
                  pauVar14 = FUN_140031398(pauVar18,(undefined1 (*) [16])&DAT_14006ad80);
                  if (pauVar14 == (undefined1 (*) [16])0x0) {
                    pwVar19 = L"#abort#";
                    pauVar12 = pauVar18;
                    pauVar14 = FUN_140031398(pauVar18,(undefined1 (*) [16])&DAT_14006ad90);
                    if (pauVar14 == (undefined1 (*) [16])0x0) {
                      pwVar19 = L"#terminate#";
                      pauVar12 = pauVar18;
                      pauVar14 = FUN_140031398(pauVar18,(undefined1 (*) [16])L"#terminate#");
                      if (pauVar14 == (undefined1 (*) [16])0x0) {
                        pwVar19 = L"debug";
                        uVar20 = FUN_140038420((ushort *)pauVar18,(ushort *)L"debug");
                        if ((int)uVar20 != 0) {
                          cVar4 = FUN_14000bfe0(pauVar18,pwVar19,uVar24);
                          if (cVar4 == '\0') {
                            FUN_14000b2a0();
                            LocalFree(hMem);
                            if (((local_950[0] == '\0') || (local_948 != (HMODULE)0x0)) &&
                               (FUN_140011e70(), local_948 != (HMODULE)0x0)) {
                              FreeLibrary(local_948);
                              local_948 = (HMODULE)0x0;
                            }
                            FUN_14000d470((longlong *)&local_338);
                          }
                          else {
                            LocalFree(hMem);
                            if (((local_950[0] == '\0') || (local_948 != (HMODULE)0x0)) &&
                               (FUN_140011e70(), local_948 != (HMODULE)0x0)) {
                              FreeLibrary(local_948);
                              local_948 = (HMODULE)0x0;
                            }
                            FUN_14000d470((longlong *)&local_338);
                          }
                          goto LAB_14000d09c;
                        }
                        cVar4 = FUN_14000bfe0(pauVar18,pwVar19,uVar24);
                        if (cVar4 != '\0') {
                          LocalFree(hMem);
                          if (((local_950[0] == '\0') || (local_948 != (HMODULE)0x0)) &&
                             (FUN_140011e70(), local_948 != (HMODULE)0x0)) {
                            FreeLibrary(local_948);
                            local_948 = (HMODULE)0x0;
                          }
                          FUN_14000d470((longlong *)&local_338);
                          goto LAB_14000d09c;
                        }
                        FUN_14000afb0();
                        goto LAB_14000d008;
                      }
                    }
                  }
                  cVar4 = FUN_14000bfe0(pauVar12,pwVar19,uVar24);
                  if (cVar4 != '\0') {
                    LocalFree(hMem);
                    if (((local_950[0] == '\0') || (local_948 != (HMODULE)0x0)) &&
                       (FUN_140011e70(), local_948 != (HMODULE)0x0)) {
                      FreeLibrary(local_948);
                      local_948 = (HMODULE)0x0;
                    }
                    FUN_14000d470((longlong *)&local_338);
                    goto LAB_14000d09c;
                  }
                  pwVar19 = L"wWinMain";
                  FUN_140002e10(local_730,0x10,0x14006b360);
                  if (local_6b0 != '\0') {
                    FUN_140012a30(local_730,0x14006b450);
                  }
                  FUN_140003090(local_730);
                  pWVar13 = DAT_14007acf0;
                  if (7 < *(ulonglong *)(DAT_14007acf0 + 0xc)) {
                    pWVar13 = *(LPCWSTR *)DAT_14007acf0;
                  }
                  local_38 = pauVar18;
                  FUN_14002aeb0(local_2e0,pWVar13,pwVar19,1,(LPCWSTR *)&local_38);
                  if (local_2b0 != '\0') {
                    puVar15 = (uint *)FUN_14002d1c0((longlong)local_2e0);
                    puVar16 = (undefined8 *)FUN_14002a6a0(local_8f8,puVar15);
                    FUN_140001a40(local_890,puVar16);
                    /* WARNING: Subroutine does not return */
                    _CxxThrowException(local_890,(ThrowInfo *)&DAT_140077818);
                  }
                }
                goto LAB_14000cffa;
              }
              FUN_14002d0a0(0,(LPCWSTR *)0x0,uVar24);
            }
          }
        }
      }
LAB_14000d008:
      LocalFree(hMem);
      if (((local_950[0] == '\0') || (local_948 != (HMODULE)0x0)) &&
         (FUN_140011e70(), local_948 != (HMODULE)0x0)) {
        FreeLibrary(local_948);
        local_948 = (HMODULE)0x0;
      }
      FUN_14000d470((longlong *)&local_338);
      goto LAB_14000d09c;
    }
    if (hMem != (LPWSTR *)0x0) {
      LocalFree(hMem);
    }
    if (((local_950[0] == '\0') || (local_948 != (HMODULE)0x0)) &&
       (FUN_140011e70(), local_948 != (HMODULE)0x0)) {
      FreeLibrary(local_948);
      local_948 = (HMODULE)0x0;
    }
  }
  FUN_14000d470((longlong *)&local_338);
LAB_14000d09c:
  FUN_14002f160(local_28 ^ (ulonglong)auStackY_9b8);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_14000d210 @ 14000d210