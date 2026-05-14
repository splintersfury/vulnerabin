void FUN_14002a810(LPCWSTR param_1)

{
  DWORD DVar1;
  BOOL BVar2;
  SC_HANDLE pSVar3;
  undefined1 auStack_168 [32];
  undefined8 local_148;
  undefined8 uStack_140;
  undefined8 local_138;
  longlong local_130 [16];
  char local_b0;
  SC_HANDLE local_38;
  char local_30;
  SC_HANDLE local_28;
  char local_20;
  ulonglong local_18;
  
  local_18 = DAT_14007a060 ^ (ulonglong)auStack_168;
  pSVar3 = OpenSCManagerW((LPCWSTR)0x0,(LPCWSTR)0x0,0xf003f);
  local_20 = pSVar3 == (SC_HANDLE)0x0;
  if ((bool)local_20) {
    DVar1 = GetLastError();
    local_28 = (SC_HANDLE)CONCAT44(local_28._4_4_,DVar1);
    FUN_140002e10(local_130,4,0x14006db58);
    if (local_b0 != '\0') {
      FUN_140012a30(local_130,0x14006db10);
    }
    if (local_20 != '\x01') {
      local_148 = 0;
      uStack_140 = 0;
      local_138 = 0;
      FUN_14000ec80(&local_148);
                    /* WARNING: Subroutine does not return */
      _CxxThrowException(&local_148,(ThrowInfo *)&DAT_1400777e0);
    }
    if (local_b0 != '\0') {
      FUN_140014c60(local_130,local_28._0_4_);
    }
    FUN_140003090(local_130);
    if (local_20 != '\x01') {
      local_148 = 0;
      uStack_140 = 0;
      local_138 = 0;
      FUN_14000ec80(&local_148);
                    /* WARNING: Subroutine does not return */
      _CxxThrowException(&local_148,(ThrowInfo *)&DAT_1400777e0);
    }
  }
  else {
    local_28 = pSVar3;
    pSVar3 = OpenServiceW(pSVar3,param_1,0x10000);
    local_30 = pSVar3 == (SC_HANDLE)0x0;
    if ((bool)local_30) {
      DVar1 = GetLastError();
      local_38 = (SC_HANDLE)CONCAT44(local_38._4_4_,DVar1);
      FUN_140002e10(local_130,4,0x14006db58);
      if (local_b0 != '\0') {
        FUN_140012a30(local_130,0x14006db78);
      }
      if (local_30 != '\x01') {
        local_148 = 0;
        uStack_140 = 0;
        local_138 = 0;
        FUN_14000ec80(&local_148);
                    /* WARNING: Subroutine does not return */
        _CxxThrowException(&local_148,(ThrowInfo *)&DAT_1400777e0);
      }
      if (local_b0 != '\0') {
        FUN_140014c60(local_130,local_38._0_4_);
      }
      FUN_140003090(local_130);
      if (local_30 != '\x01') {
        local_148 = 0;
        uStack_140 = 0;
        local_138 = 0;
        FUN_14000ec80(&local_148);
                    /* WARNING: Subroutine does not return */
        _CxxThrowException(&local_148,(ThrowInfo *)&DAT_1400777e0);
      }
    }
    else {
      local_38 = pSVar3;
      BVar2 = DeleteService(pSVar3);
      if (BVar2 == 0) {
        GetLastError();
      }
    }
    if (((local_30 != -1) && (local_30 == '\0')) && (local_38 != (SC_HANDLE)0x0)) {
      CloseServiceHandle(local_38);
    }
  }
  if (((local_20 != -1) && (local_20 == '\0')) && (local_28 != (SC_HANDLE)0x0)) {
    CloseServiceHandle(local_28);
  }
  FUN_14002f160(local_18 ^ (ulonglong)auStack_168);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_14002aaa0 @ 14002aaa0