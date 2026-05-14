void FUN_14000a600(longlong param_1)

{
  LSTATUS LVar1;
  BOOL BVar2;
  SC_HANDLE hService;
  int iVar3;
  undefined **ppuVar4;
  LPCWSTR ***lpSubKey;
  undefined1 auStackY_c8 [32];
  HKEY local_88;
  int local_80 [2];
  undefined8 local_78;
  undefined8 uStack_70;
  LPCWSTR **local_58 [3];
  ulonglong local_40;
  char local_38;
  _SERVICE_STATUS local_30;
  ulonglong local_10;
  
  local_10 = DAT_14007a060 ^ (ulonglong)auStackY_c8;
  if (*(char *)(param_1 + 0x20) == '\0') {
    local_38 = '\0';
  }
  else {
    FUN_140009170(param_1,local_58,0x7d1,L"common");
    if (local_38 != '\0') {
      lpSubKey = local_58;
      if (7 < local_40) {
        lpSubKey = (LPCWSTR ***)local_58[0];
      }
      local_80[0] = 0;
      local_88 = (HKEY)CONCAT44(local_88._4_4_,4);
      LVar1 = RegGetValueW((HKEY)0xffffffff80000002,(LPCWSTR)lpSubKey,L"NoRestrictBDAppsOnUpdate",
                           0x10,(LPDWORD)0x0,local_80,(LPDWORD)&local_88);
      if (LVar1 == 0) {
        ppuVar4 = &PTR_vftable_14007ac70;
        LVar1 = 0;
      }
      else {
        local_78 = CONCAT44(local_78._4_4_,LVar1);
        uStack_70 = &PTR_vftable_14007ad08;
        ppuVar4 = &PTR_vftable_14007ad08;
      }
      if ((((ppuVar4[1] == DAT_14007ac78) && (iVar3 = local_80[0], LVar1 == 0)) ||
          (iVar3 = 0, ppuVar4[1] == DAT_14007ac78)) && ((LVar1 == 0 && (iVar3 != 0)))) {
        FUN_14000d470((longlong *)local_58);
        goto LAB_14000a6f1;
      }
    }
  }
  FUN_14000d470((longlong *)local_58);
  local_88 = (HKEY)0x0;
  LVar1 = RegOpenKeyExW((HKEY)0xffffffff80000003,L".DEFAULT\\Software\\SetID\\bd.update.configure",0
                        ,0x20019,&local_88);
  if ((LVar1 == 0) && (local_88 != (HKEY)0x0)) {
    RegCloseKey(local_88);
    local_88 = (HKEY)0x0;
    FUN_14000a500(&local_88);
    if (local_88 != (HKEY)0x0) {
      hService = OpenServiceW((SC_HANDLE)local_88,L"UPDATESRV",4);
      if (hService == (SC_HANDLE)0x0) {
        GetLastError();
      }
      else {
        BVar2 = QueryServiceStatus(hService,&local_30);
        if (BVar2 == 0) {
          GetLastError();
          local_78 = 0;
          uStack_70 = (undefined **)0x0;
        }
        else {
          local_78 = CONCAT44(local_30.dwCurrentState,local_30.dwServiceType);
          uStack_70 = (undefined **)CONCAT44(local_30.dwWin32ExitCode,local_30.dwControlsAccepted);
        }
        CloseServiceHandle(hService);
      }
      if (local_88 != (HKEY)0x0) {
        CloseServiceHandle((SC_HANDLE)local_88);
      }
    }
  }
LAB_14000a6f1:
  FUN_14002f160(local_10 ^ (ulonglong)auStackY_c8);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_14000a810 @ 14000a810