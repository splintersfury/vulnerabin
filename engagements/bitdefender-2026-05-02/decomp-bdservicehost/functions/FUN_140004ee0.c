void FUN_140004ee0(LPCWSTR param_1,DWORD *param_2)

{
  bool bVar1;
  BOOL BVar2;
  DWORD DVar3;
  HANDLE hFile;
  BYTE *pbHash;
  undefined **ppuVar4;
  undefined1 auStackY_388 [32];
  DWORD DStack_344;
  DWORD local_338 [2];
  HCATINFO local_330;
  HCATADMIN local_328 [2];
  undefined8 local_318;
  undefined8 local_310;
  undefined8 local_308;
  undefined8 local_300;
  undefined8 local_2f8;
  undefined8 *local_2f0;
  undefined8 local_2e8;
  undefined8 local_2e0;
  undefined8 local_2d8;
  undefined8 local_2d0;
  undefined8 local_2c8;
  undefined8 local_2b8;
  WCHAR *local_2b0;
  undefined8 local_2a8;
  LPCWSTR local_2a0;
  HANDLE local_298;
  BYTE *local_290;
  uint local_288;
  undefined8 local_284;
  undefined8 local_27c;
  undefined4 local_274;
  GUID local_268;
  CATALOG_INFO local_258;
  ulonglong local_48;
  
  local_48 = DAT_14007a060 ^ (ulonglong)auStackY_388;
  hFile = CreateFileW(param_1,0x80000000,1,(LPSECURITY_ATTRIBUTES)0x0,3,0x80,
                      (HANDLE)0xffffffffffffffff);
  if (hFile == (HANDLE)0xffffffffffffffff) {
    local_268.Data1 = GetLastError();
    local_268.Data4 = (uchar  [8])&PTR_vftable_14007ad08;
    *param_2 = local_268.Data1;
    param_2[1] = local_268._4_4_;
    param_2[2] = 0x4007ad08;
    param_2[3] = 1;
    ppuVar4 = *(undefined ***)(param_2 + 2);
  }
  else {
    *param_2 = 0;
    ppuVar4 = &PTR_vftable_14007ac70;
    *(undefined ***)(param_2 + 2) = &PTR_vftable_14007ac70;
  }
  if ((ppuVar4[1] == DAT_14007ac78) && (*param_2 == 0)) {
    local_338[0] = 0;
    BVar2 = CryptCATAdminCalcHashFromFileHandle(hFile,local_338,(BYTE *)0x0,0);
    if ((BVar2 == 0) && (DVar3 = GetLastError(), DVar3 != 0x7a)) {
      local_268.Data1 = GetLastError();
    }
    else {
      pbHash = (BYTE *)thunk_FUN_14002fe08((ulonglong)local_338[0]);
      if (pbHash != (BYTE *)0x0) {
        BVar2 = CryptCATAdminCalcHashFromFileHandle(hFile,local_338,pbHash,0);
        if (BVar2 != 0) {
          local_328[0] = (HCATADMIN)0x0;
          BVar2 = CryptCATAdminAcquireContext(local_328,(GUID *)0x0,0);
          if (BVar2 != 0) {
            local_330 = (HCATINFO)0x0;
            local_330 = CryptCATAdminEnumCatalogFromHash
                                  (local_328[0],pbHash,local_338[0],0,&local_330);
            while (local_330 != (HCATINFO)0x0) {
              local_258.cbStruct = 0x20c;
              BVar2 = CryptCATCatalogInfoFromContext(local_330,&local_258,0);
              if (BVar2 != 0) {
                local_288 = local_338[0];
                local_2b0 = local_258.wszCatalogFile;
                local_2b8 = 0x48;
                local_2a8 = 0;
                local_2e8 = 0;
                local_2c8 = 0;
                local_2f0 = &local_2b8;
                local_284 = 0;
                local_27c = 0;
                local_274 = 0;
                local_268.Data1 = 0xaac56b;
                local_268.Data2 = 0xcd44;
                local_268.Data3 = 0x11d0;
                local_268.Data4[0] = 0x8c;
                local_268.Data4[1] = 0xc2;
                local_268.Data4[2] = '\0';
                local_268.Data4[3] = 0xc0;
                local_268.Data4[4] = 'O';
                local_268.Data4[5] = 0xc2;
                local_268.Data4[6] = 0x95;
                local_268.Data4[7] = 0xee;
                local_318 = 0x58;
                local_2f8 = 2;
                local_310 = 0;
                local_308 = 0;
                local_300 = 2;
                local_2e0 = 0;
                local_2d8 = 0;
                local_2d0 = 0x1000;
                local_2a0 = param_1;
                local_298 = hFile;
                local_290 = pbHash;
                DVar3 = WinVerifyTrust((HWND)0x0,&local_268,&local_318);
                if (DVar3 == 0) {
                  *param_2 = 0;
                  bVar1 = true;
                  *(undefined ***)(param_2 + 2) = &PTR_vftable_14007ac70;
                  ppuVar4 = &PTR_vftable_14007ac70;
                }
                else {
                  bVar1 = false;
                  if (DVar3 == 0x800b0004) {
                    *param_2 = 0;
                    ppuVar4 = &PTR_vftable_14007ac70;
                    *(undefined ***)(param_2 + 2) = &PTR_vftable_14007ac70;
                  }
                  else {
                    *param_2 = DVar3;
                    param_2[1] = DStack_344;
                    param_2[2] = 0x4007ad08;
                    param_2[3] = 1;
                    ppuVar4 = *(undefined ***)(param_2 + 2);
                  }
                }
                if (((ppuVar4[1] == DAT_14007ac78) && (*param_2 == 0)) && (bVar1)) break;
              }
              local_330 = CryptCATAdminEnumCatalogFromHash
                                    (local_328[0],pbHash,local_338[0],0,&local_330);
            }
            if (local_328[0] != (HCATADMIN)0x0) {
              CryptCATAdminReleaseContext(local_328[0],0);
            }
            FUN_14002f180();
            if (hFile != (HANDLE)0xffffffffffffffff) {
              CloseHandle(hFile);
            }
            goto LAB_140004fe2;
          }
        }
        local_268.Data1 = GetLastError();
        local_268.Data4 = (uchar  [8])&PTR_vftable_14007ad08;
        *(ulonglong *)param_2 = CONCAT44(local_268._4_4_,local_268.Data1);
        *(undefined ***)(param_2 + 2) = &PTR_vftable_14007ad08;
        FUN_14002f180();
        goto LAB_140004fd1;
      }
      local_268.Data1 = 0xe;
    }
    local_268.Data4 = (uchar  [8])&PTR_vftable_14007ad08;
    *param_2 = local_268.Data1;
    param_2[1] = local_268._4_4_;
    param_2[2] = 0x4007ad08;
    param_2[3] = 1;
  }
LAB_140004fd1:
  if (hFile != (HANDLE)0xffffffffffffffff) {
    CloseHandle(hFile);
  }
LAB_140004fe2:
  FUN_14002f160(local_48 ^ (ulonglong)auStackY_388);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_140005250 @ 140005250