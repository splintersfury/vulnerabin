void FUN_14002b4e0(undefined8 *param_1,LPCWSTR param_2)

{
  DWORD DVar1;
  SC_HANDLE pSVar2;
  bool bVar3;
  undefined1 auStack_b8 [32];
  undefined8 local_98;
  undefined4 uStack_90;
  undefined4 uStack_8c;
  undefined8 local_88;
  undefined8 uStack_80;
  undefined8 *local_78;
  undefined8 local_70;
  undefined **ppuStack_68;
  undefined8 local_60;
  SC_HANDLE local_40;
  char local_38;
  SC_HANDLE local_30;
  char local_28;
  ulonglong local_20;
  
  local_20 = DAT_14007a060 ^ (ulonglong)auStack_b8;
  local_78 = param_1;
  pSVar2 = OpenSCManagerW((LPCWSTR)0x0,(LPCWSTR)0x0,0xf003f);
  local_38 = pSVar2 == (SC_HANDLE)0x0;
  if ((bool)local_38) {
    DVar1 = GetLastError();
    local_40 = (SC_HANDLE)CONCAT44(local_40._4_4_,DVar1);
    if (!(bool)local_38) {
      local_70 = 0;
      ppuStack_68 = (undefined **)0x0;
      local_60 = 0;
      FUN_14000ec80(&local_70);
                    /* WARNING: Subroutine does not return */
      _CxxThrowException(&local_70,(ThrowInfo *)&DAT_1400777e0);
    }
    local_98 = 0;
    local_88 = 0;
    uStack_80 = 0xf;
    FUN_1400106a0(&local_98,(undefined8 *)"open_sc_manager failed",0x16);
    local_70 = CONCAT44(local_70._4_4_,DVar1);
    ppuStack_68 = &PTR_vftable_14007ad08;
    *param_1 = local_70;
    param_1[1] = &PTR_vftable_14007ad08;
    *(undefined4 *)(param_1 + 2) = (undefined4)local_98;
    *(undefined4 *)((longlong)param_1 + 0x14) = local_98._4_4_;
    *(undefined4 *)(param_1 + 3) = uStack_90;
    *(undefined4 *)((longlong)param_1 + 0x1c) = uStack_8c;
    param_1[4] = local_88;
    param_1[5] = uStack_80;
    *(undefined1 *)(param_1 + 6) = 1;
  }
  else {
    local_40 = pSVar2;
    pSVar2 = OpenServiceW(pSVar2,param_2,0x24);
    bVar3 = pSVar2 == (SC_HANDLE)0x0;
    local_28 = bVar3;
    if (bVar3) {
      DVar1 = GetLastError();
      local_30 = (SC_HANDLE)CONCAT44(local_30._4_4_,DVar1);
      if (!bVar3) {
        local_70 = 0;
        ppuStack_68 = (undefined **)0x0;
        local_60 = 0;
        FUN_14000ec80(&local_70);
                    /* WARNING: Subroutine does not return */
        _CxxThrowException(&local_70,(ThrowInfo *)&DAT_1400777e0);
      }
      local_98 = 0;
      local_88 = 0;
      uStack_80 = 0xf;
      FUN_1400106a0(&local_98,(undefined8 *)"open_service failed",0x13);
      local_70 = CONCAT44(local_70._4_4_,DVar1);
      ppuStack_68 = &PTR_vftable_14007ad08;
      *param_1 = local_70;
      param_1[1] = &PTR_vftable_14007ad08;
      *(undefined4 *)(param_1 + 2) = (undefined4)local_98;
      *(undefined4 *)((longlong)param_1 + 0x14) = local_98._4_4_;
      *(undefined4 *)(param_1 + 3) = uStack_90;
      *(undefined4 *)((longlong)param_1 + 0x1c) = uStack_8c;
      *(undefined4 *)(param_1 + 4) = (undefined4)local_88;
      *(undefined4 *)((longlong)param_1 + 0x24) = local_88._4_4_;
      *(undefined4 *)(param_1 + 5) = (undefined4)uStack_80;
      *(undefined4 *)((longlong)param_1 + 0x2c) = uStack_80._4_4_;
      *(undefined1 *)(param_1 + 6) = 1;
      if (((local_28 != -1) && (local_28 == '\0')) && (local_30 != (SC_HANDLE)0x0)) {
        CloseServiceHandle(local_30);
      }
    }
    else {
      local_30 = pSVar2;
      FUN_14002b350(param_1,pSVar2);
      if (((local_28 != -1) && (local_28 == '\0')) && (local_30 != (SC_HANDLE)0x0)) {
        CloseServiceHandle(local_30);
      }
    }
  }
  if (((local_38 != -1) && (local_38 == '\0')) && (local_40 != (SC_HANDLE)0x0)) {
    CloseServiceHandle(local_40);
  }
  FUN_14002f160(local_20 ^ (ulonglong)auStack_b8);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_14002b740 @ 14002b740