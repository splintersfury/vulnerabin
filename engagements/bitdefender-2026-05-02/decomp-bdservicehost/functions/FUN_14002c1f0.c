void FUN_14002c1f0(SC_HANDLE param_1,uint param_2)

{
  uint uVar1;
  uint uVar2;
  BOOL BVar3;
  DWORD DVar4;
  DWORD DVar5;
  DWORD DVar6;
  undefined1 auStack_188 [32];
  DWORD local_168;
  DWORD DStack_164;
  DWORD DStack_160;
  DWORD DStack_15c;
  longlong local_148 [16];
  char local_c8;
  _SERVICE_STATUS local_50;
  ulonglong local_30;
  
  local_30 = DAT_14007a060 ^ (ulonglong)auStack_188;
  BVar3 = QueryServiceStatus(param_1,&local_50);
  if ((BVar3 == 0) && (DVar4 = GetLastError(), DVar4 != 0)) {
    FUN_140002e10(local_148,4,0x14006ddb8);
    if ((local_c8 != '\0') && (FUN_140012a30(local_148,0x14006dd40), local_c8 != '\0')) {
      FUN_140014c60(local_148,DVar4);
    }
    FUN_140003090(local_148);
  }
  else {
    uVar2 = local_50.dwWaitHint;
    local_168 = local_50.dwServiceType;
    DStack_164 = local_50.dwCurrentState;
    DStack_160 = local_50.dwControlsAccepted;
    DStack_15c = local_50.dwWin32ExitCode;
    if ((local_50.dwCurrentState - 1 & 0xfffffffd) == 0) {
      DVar5 = GetTickCount();
      DVar4 = DVar5;
      uVar1 = local_50.dwCheckPoint;
      do {
        while( true ) {
          if ((local_50.dwCurrentState != 3) ||
             ((param_2 != 0 && (DVar6 = GetTickCount(), param_2 < DVar6 - DVar5))))
          goto LAB_14002c373;
          DVar6 = uVar2 / 10;
          if (DVar6 < 1000) {
            DVar6 = 1000;
          }
          else if (10000 < DVar6) {
            DVar6 = 10000;
          }
          Sleep(DVar6);
          BVar3 = QueryServiceStatus(param_1,&local_50);
          if (BVar3 == 0) {
            DVar6 = GetLastError();
          }
          else {
            DVar6 = 0;
          }
          uVar2 = local_50.dwWaitHint;
          if (DVar6 != 0) {
            FUN_140002e10(local_148,4,0x14006ddb8);
            if ((local_c8 != '\0') && (FUN_140012a30(local_148,0x14006dd40), local_c8 != '\0')) {
              FUN_140014c60(local_148,DVar6);
            }
            FUN_140003090(local_148);
            goto LAB_14002c373;
          }
          local_168 = local_50.dwServiceType;
          DStack_164 = local_50.dwCurrentState;
          DStack_160 = local_50.dwControlsAccepted;
          DStack_15c = local_50.dwWin32ExitCode;
          if (local_50.dwCheckPoint <= uVar1) break;
          DVar4 = GetTickCount();
          uVar1 = local_50.dwCheckPoint;
        }
        DVar6 = GetTickCount();
      } while (DVar6 - DVar4 <= uVar2);
    }
  }
LAB_14002c373:
  FUN_14002f160(local_30 ^ (ulonglong)auStack_188);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_14002c3f0 @ 14002c3f0