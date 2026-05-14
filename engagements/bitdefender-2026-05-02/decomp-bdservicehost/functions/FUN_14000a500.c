void FUN_14000a500(undefined8 *param_1)

{
  undefined **ppuVar1;
  DWORD DVar2;
  SC_HANDLE pSVar3;
  undefined4 uVar4;
  undefined4 uVar5;
  undefined1 auStack_88 [32];
  undefined4 local_68;
  undefined8 *local_60;
  undefined8 local_58 [6];
  undefined8 local_28;
  undefined8 uStack_20;
  ulonglong local_18;
  
  local_18 = DAT_14007a060 ^ (ulonglong)auStack_88;
  local_68 = 0;
  local_28 = 0;
  uStack_20 = (undefined **)0x0;
  *param_1 = 0;
  local_60 = param_1;
  pSVar3 = OpenSCManagerW((LPCWSTR)0x0,(LPCWSTR)0x0,0xf003f);
  if (pSVar3 == (SC_HANDLE)0x0) {
    DVar2 = GetLastError();
    uStack_20._0_4_ = 0x4007ad08;
    uVar5 = (undefined4)uStack_20;
    local_28 = CONCAT44(local_28._4_4_,DVar2);
    uStack_20 = &PTR_vftable_14007ad08;
    uVar4 = local_28._4_4_;
  }
  else {
    uStack_20 = &PTR_vftable_14007ac70;
    ppuVar1 = uStack_20;
    uStack_20._0_4_ = 0x4007ac70;
    DVar2 = (DWORD)local_28;
    uVar4 = local_28._4_4_;
    uVar5 = (undefined4)uStack_20;
    uStack_20 = ppuVar1;
  }
  *param_1 = pSVar3;
  local_68 = 1;
  if ((uStack_20[1] == DAT_14007ac78) && (DVar2 == 0)) {
    FUN_14002f160(local_18 ^ (ulonglong)auStack_88);
    return;
  }
  local_28 = CONCAT44(uVar4,DVar2);
  uStack_20 = (undefined **)CONCAT44(1,uVar5);
  FUN_140003760(local_58,&local_28,(undefined8 *)"OpenSCManager failed");
                    /* WARNING: Subroutine does not return */
  _CxxThrowException(local_58,(ThrowInfo *)&DAT_140077a60);
}


// FUNCTION_END

// FUNCTION_START: FUN_14000a600 @ 14000a600