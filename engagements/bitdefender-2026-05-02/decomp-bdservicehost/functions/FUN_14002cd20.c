void FUN_14002cd20(void)

{
  code *pcVar1;
  DWORD DVar2;
  SC_HANDLE hSCManager;
  SC_HANDLE hSCObject;
  undefined8 *puVar3;
  uint *puVar4;
  LPCWSTR lpServiceName;
  undefined1 auStack_1e8 [32];
  undefined8 local_1c8;
  undefined8 uStack_1c0;
  undefined8 local_1b8;
  undefined1 local_1b0;
  undefined7 uStack_1af;
  undefined8 local_1a0;
  ulonglong local_198;
  longlong local_190 [16];
  char local_110;
  SC_HANDLE local_98;
  undefined **ppuStack_90;
  SC_HANDLE local_88;
  uint local_80 [12];
  char local_50;
  undefined8 local_48 [6];
  char local_18;
  ulonglong local_10;
  
  local_10 = DAT_14007a060 ^ (ulonglong)auStack_1e8;
  hSCManager = OpenSCManagerW((LPCWSTR)0x0,(LPCWSTR)0x0,4);
  local_88 = hSCManager;
  if (hSCManager == (SC_HANDLE)0x0) {
    DVar2 = GetLastError();
    local_98 = (SC_HANDLE)CONCAT44(local_98._4_4_,DVar2);
    ppuStack_90 = &PTR_vftable_14007ad08;
    FUN_140002e10(local_190,4,0x14006e020);
    if ((local_110 != '\0') && (FUN_140012a30(local_190,0x14006dfd0), local_110 != '\0')) {
      FUN_14000e200(local_190,DVar2);
    }
    FUN_140003090(local_190);
    goto LAB_14002d00a;
  }
  lpServiceName = DAT_14007acf0;
  if (7 < *(ulonglong *)(DAT_14007acf0 + 0xc)) {
    lpServiceName = *(LPCWSTR *)DAT_14007acf0;
  }
  hSCObject = OpenServiceW(hSCManager,lpServiceName,0x102);
  local_98 = hSCObject;
  if (hSCObject == (SC_HANDLE)0x0) {
    DVar2 = GetLastError();
    ppuStack_90 = &PTR_vftable_14007ad08;
    FUN_140002e10(local_190,4,0x14006e020);
    if ((local_110 != '\0') && (FUN_140012a30(local_190,0x14006e068), local_110 != '\0')) {
      FUN_14000e200(local_190,DVar2);
    }
    FUN_140003090(local_190);
  }
  else {
    if ((char)DAT_14007acf0[0x74] != '\0') {
      FUN_14002aaa0((undefined8 *)local_80,hSCObject,0x81);
      if (local_50 != '\0') {
        FUN_140002e10(local_190,4,0x14006e020);
        if (local_110 != '\0') {
          FUN_140012a30(local_190,0x14006e0b0);
        }
        if (local_50 == '\0') {
          local_1c8 = 0;
          uStack_1c0 = 0;
          local_1b8 = 0;
          FUN_14000ec80(&local_1c8);
                    /* WARNING: Subroutine does not return */
          _CxxThrowException(&local_1c8,(ThrowInfo *)&DAT_1400777e0);
        }
        puVar3 = (undefined8 *)FUN_14002a6a0((longlong *)&local_1b0,local_80);
        if (0xf < (ulonglong)puVar3[3]) {
          puVar3 = (undefined8 *)*puVar3;
        }
        if (local_110 != '\0') {
          FUN_1400144b0(local_190,(undefined1 *)puVar3);
        }
        if (0xf < local_198) {
          if ((0xfff < local_198 + 1) &&
             (0x1f < (CONCAT71(uStack_1af,local_1b0) -
                     *(longlong *)(CONCAT71(uStack_1af,local_1b0) + -8)) - 8U)) {
            FUN_140035d28();
            pcVar1 = (code *)swi(3);
            (*pcVar1)();
            return;
          }
          FUN_14002f180();
        }
        local_1a0 = 0;
        local_198 = 0xf;
        local_1b0 = 0;
        FUN_140003090(local_190);
        FUN_14002d150((longlong)local_80);
        CloseServiceHandle(hSCObject);
        goto LAB_14002d001;
      }
      FUN_14002d150((longlong)local_80);
    }
    FUN_14002b740(local_48,hSCObject,4);
    if (local_18 != '\0') {
      puVar4 = (uint *)FUN_14002d1c0((longlong)local_48);
      puVar3 = (undefined8 *)FUN_14002a6a0((longlong *)&local_1b0,puVar4);
      FUN_140001a40(&local_1c8,puVar3);
                    /* WARNING: Subroutine does not return */
      _CxxThrowException(&local_1c8,(ThrowInfo *)&DAT_140077818);
    }
    FUN_14002d150((longlong)local_48);
    CloseServiceHandle(hSCObject);
  }
LAB_14002d001:
  CloseServiceHandle(hSCManager);
LAB_14002d00a:
  FUN_14002f160(local_10 ^ (ulonglong)auStack_1e8);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_14002d0a0 @ 14002d0a0