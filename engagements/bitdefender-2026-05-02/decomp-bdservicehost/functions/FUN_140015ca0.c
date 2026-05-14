void FUN_140015ca0(longlong *param_1,int param_2,undefined4 param_3,undefined8 param_4)

{
  int iVar1;
  int iVar2;
  char cVar3;
  undefined8 *puVar4;
  LPCWSTR pWVar5;
  undefined1 auStackY_628 [32];
  HMODULE *local_5e8;
  int local_5e0;
  undefined4 local_5d8 [2];
  undefined1 local_5d0;
  undefined7 uStack_5cf;
  undefined8 local_5c0;
  ulonglong local_5b8;
  undefined8 local_5b0;
  undefined8 uStack_5a8;
  undefined8 local_5a0;
  longlong local_598 [16];
  char local_518;
  uint local_4a0 [12];
  char local_470;
  DWORD local_468;
  wchar_t local_464 [260];
  wchar_t local_25c [266];
  ulonglong local_48;
  
  local_48 = DAT_14007a060 ^ (ulonglong)auStackY_628;
  local_468 = timeGetTime();
  wcsncpy_s(local_464,0x102,L"service::on_control_handler",0xffffffffffffffff);
  wcscat_s(local_464,0x104,L"()");
  wcsncpy_s(local_25c,0x104,L"service::on_control_handler",0xffffffffffffffff);
  if (DAT_14007d500 + DAT_14007d504 != 0) {
    local_5e8 = FUN_14000eb20();
    LOCK();
    local_5e0 = 1;
    UNLOCK();
    if (local_5e8 == (HMODULE *)0x0) {
      local_5e8 = FUN_14000eb20();
      LOCK();
      local_5e0 = 2;
      UNLOCK();
    }
    local_5d8[0] = 0x20;
    FUN_1400019c0((longlong)local_5e8,1,local_5d8,&IMAGE_DOS_HEADER_140000000,local_25c,L"-> %s");
    LOCK();
    UNLOCK();
    iVar1 = local_5e0 + -1;
    iVar2 = local_5e0;
    while (-1 < iVar1) {
      local_5e0 = iVar2 + -1;
      FUN_140011e70();
      LOCK();
      UNLOCK();
      iVar1 = iVar2 + -2;
      iVar2 = local_5e0;
    }
    LOCK();
    UNLOCK();
  }
  if ((param_2 != 1) && (param_2 != 5)) {
    if (param_2 != 0x80) {
      if ((param_2 == 0x81) && (cVar3 = FUN_140016820(param_1), cVar3 != '\0')) {
        pWVar5 = DAT_14007acf0;
        if (7 < *(ulonglong *)(DAT_14007acf0 + 0xc)) {
          pWVar5 = *(LPCWSTR *)DAT_14007acf0;
        }
        FUN_14002bca0((undefined8 *)local_4a0,pWVar5);
        if (local_470 != '\0') {
          FUN_140002e10(local_598,4,0x14006e0f0);
          if (local_470 == '\0') {
LAB_140015f8d:
            local_5b0 = 0;
            uStack_5a8 = 0;
            local_5a0 = 0;
            FUN_14000ec80(&local_5b0);
                    /* WARNING: Subroutine does not return */
            _CxxThrowException(&local_5b0,(ThrowInfo *)&DAT_1400777e0);
          }
          puVar4 = (undefined8 *)FUN_14002a6a0((longlong *)&local_5d0,local_4a0);
          if (0xf < (ulonglong)puVar4[3]) {
            puVar4 = (undefined8 *)*puVar4;
          }
          if (local_518 != '\0') {
            FUN_1400144b0(local_598,(undefined1 *)puVar4);
          }
          if (0xf < local_5b8) {
            if ((0xfff < local_5b8 + 1) &&
               (0x1f < (CONCAT71(uStack_5cf,local_5d0) -
                       *(longlong *)(CONCAT71(uStack_5cf,local_5d0) + -8)) - 8U)) {
              FUN_140035d28();
              goto LAB_140015f8d;
            }
            FUN_14002f180();
          }
          local_5c0 = 0;
          local_5b8 = 0xf;
          local_5d0 = 0;
          FUN_140003090(local_598);
        }
        FUN_14002d150((longlong)local_4a0);
      }
      goto LAB_140015f36;
    }
    cVar3 = FUN_140016820(param_1);
    if (cVar3 == '\0') goto LAB_140015f36;
  }
  if ((HANDLE)param_1[1] != (HANDLE)0x0) {
    SetEvent((HANDLE)param_1[1]);
  }
LAB_140015f36:
  (*(code *)PTR__guard_dispatch_icall_14005b538)(param_1[4],param_2,param_3,param_4);
  FUN_140015270((longlong)&local_468);
  FUN_14002f160(local_48 ^ (ulonglong)auStackY_628);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_140015fc0 @ 140015fc0