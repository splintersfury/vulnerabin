void FUN_140019ac0(longlong param_1,HANDLE param_2)

{
  int iVar1;
  int iVar2;
  bool bVar3;
  HPOWERNOTIFY pvVar4;
  undefined4 local_res18 [2];
  HMODULE *local_18;
  int local_10;
  
  if (param_2 != (HANDLE)0x0) {
    bVar3 = false;
    pvVar4 = RegisterPowerSettingNotification(param_2,(LPCGUID)&DAT_14005bb30,1);
    *(HPOWERNOTIFY *)(param_1 + 8) = pvVar4;
    if (pvVar4 == (HPOWERNOTIFY)0x0) {
      if (DAT_14007d500 + DAT_14007d504 != 0) {
        local_18 = FUN_14000eb20();
        LOCK();
        local_10 = 1;
        UNLOCK();
        bVar3 = true;
        if (local_18 == (HMODULE *)0x0) {
          local_18 = FUN_14000eb20();
          LOCK();
          local_10 = 2;
          UNLOCK();
        }
        GetLastError();
        local_res18[0] = 8;
        FUN_1400019c0((longlong)local_18,0,local_res18,&IMAGE_DOS_HEADER_140000000,
                      L"CBdServicePowerSourceEvent::Register",
                      L"RegisterPowerSettingNotification GUID_ACDC_POWER_SOURCE failed err=%d");
      }
      if (bVar3) {
        LOCK();
        UNLOCK();
        iVar1 = local_10 + -1;
        iVar2 = local_10;
        while (-1 < iVar1) {
          local_10 = iVar2 + -1;
          FUN_140011e70();
          LOCK();
          UNLOCK();
          iVar1 = iVar2 + -2;
          iVar2 = local_10;
        }
        LOCK();
        UNLOCK();
      }
      *(undefined8 *)(param_1 + 8) = 0;
    }
  }
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_140019bf0 @ 140019bf0