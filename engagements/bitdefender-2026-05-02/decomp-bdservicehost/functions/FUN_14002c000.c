void FUN_14002c000(SC_HANDLE param_1)

{
  uint uVar1;
  uint uVar2;
  BOOL BVar3;
  DWORD DVar4;
  DWORD DVar5;
  undefined1 auStack_178 [64];
  longlong local_138 [16];
  char local_b8;
  _SERVICE_STATUS local_40;
  ulonglong local_20;
  
  local_20 = DAT_14007a060 ^ (ulonglong)auStack_178;
  BVar3 = QueryServiceStatus(param_1,&local_40);
  if ((BVar3 == 0) && (DVar4 = GetLastError(), DVar4 != 0)) {
    FUN_140002e10(local_138,4,0x14006dd88);
    if ((local_b8 != '\0') && (FUN_140012a30(local_138,0x14006dd40), local_b8 != '\0')) {
      FUN_140014c60(local_138,DVar4);
    }
    FUN_140003090(local_138);
  }
  else {
    uVar2 = local_40.dwWaitHint;
    auStack_178._40_4_ = local_40.dwControlsAccepted;
    auStack_178._44_4_ = local_40.dwWin32ExitCode;
    DVar4 = GetTickCount();
    uVar1 = local_40.dwCheckPoint;
    do {
      while( true ) {
        if (local_40.dwCurrentState != 2) goto LAB_14002c14f;
        GetTickCount();
        DVar5 = uVar2 / 10;
        if (DVar5 < 1000) {
          DVar5 = 1000;
        }
        else if (10000 < DVar5) {
          DVar5 = 10000;
        }
        Sleep(DVar5);
        BVar3 = QueryServiceStatus(param_1,&local_40);
        if (BVar3 == 0) {
          DVar5 = GetLastError();
        }
        else {
          DVar5 = 0;
        }
        uVar2 = local_40.dwWaitHint;
        if (DVar5 != 0) {
          FUN_140002e10(local_138,4,0x14006dd88);
          if ((local_b8 != '\0') && (FUN_140012a30(local_138,0x14006dd40), local_b8 != '\0')) {
            FUN_140014c60(local_138,DVar5);
          }
          FUN_140003090(local_138);
          goto LAB_14002c14f;
        }
        auStack_178._40_4_ = local_40.dwControlsAccepted;
        auStack_178._44_4_ = local_40.dwWin32ExitCode;
        if ((local_40.dwCheckPoint <= uVar1) && (local_40.dwCheckPoint != 0)) break;
        DVar4 = GetTickCount();
        uVar1 = local_40.dwCheckPoint;
      }
      DVar5 = GetTickCount();
    } while (DVar5 - DVar4 <= uVar2);
  }
LAB_14002c14f:
  FUN_14002f160(local_20 ^ (ulonglong)auStack_178);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_14002c1f0 @ 14002c1f0