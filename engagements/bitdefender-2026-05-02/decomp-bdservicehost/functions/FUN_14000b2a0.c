void FUN_14000b2a0(void)

{
  BOOL BVar1;
  DWORD DVar2;
  wchar_t *pwVar3;
  undefined1 auStack_148 [32];
  longlong local_128 [16];
  char local_a8;
  SERVICE_TABLE_ENTRYW local_30;
  undefined8 local_20;
  undefined8 local_18;
  ulonglong local_10;
  
  local_10 = DAT_14007a060 ^ (ulonglong)auStack_148;
  pwVar3 = DAT_14007acf0;
  if (7 < *(ulonglong *)(DAT_14007acf0 + 0xc)) {
    pwVar3 = *(wchar_t **)DAT_14007acf0;
  }
  pwVar3 = _wcsdup(pwVar3);
  local_30.lpServiceProc = FUN_14000ac10;
  local_20 = 0;
  local_18 = 0;
  local_30.lpServiceName = pwVar3;
  BVar1 = StartServiceCtrlDispatcherW(&local_30);
  if (BVar1 == 0) {
    FUN_140002e10(local_128,4,0x14006b220);
    if (local_a8 != '\0') {
      FUN_140012a30(local_128,0x14006b1c0);
    }
    DVar2 = GetLastError();
    if (local_a8 != '\0') {
      FUN_140014c60(local_128,DVar2);
    }
    FUN_140003090(local_128);
  }
  FUN_140035ac0(pwVar3);
  FUN_14002f160(local_10 ^ (ulonglong)auStack_148);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_14000b390 @ 14000b390