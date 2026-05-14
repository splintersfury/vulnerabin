void FUN_14000b390(void)

{
  code *pcVar1;
  BOOL BVar2;
  DWORD DVar3;
  LPWSTR pWVar4;
  LPCWSTR lpPathName;
  undefined1 auStack_198 [32];
  undefined4 local_178;
  undefined4 uStack_174;
  undefined4 uStack_170;
  undefined4 uStack_16c;
  undefined8 local_168;
  ulonglong uStack_160;
  longlong local_158 [3];
  ulonglong local_140;
  longlong local_130 [16];
  char local_b0;
  undefined8 local_38;
  undefined4 uStack_30;
  undefined4 uStack_2c;
  undefined8 local_28;
  ulonglong uStack_20;
  ulonglong local_18;
  
  local_18 = DAT_14007a060 ^ (ulonglong)auStack_198;
  local_28 = 0;
  uStack_20 = 7;
  local_38 = 0;
  pWVar4 = FUN_1400060a0((LPWSTR)local_158);
  if ((LPWSTR)&local_38 == pWVar4) {
    local_178 = (undefined4)local_38;
    uStack_174 = local_38._4_4_;
  }
  else {
    local_178 = *(undefined4 *)pWVar4;
    local_38 = *(ulonglong *)pWVar4;
    uStack_30 = *(undefined4 *)(pWVar4 + 4);
    uStack_2c = *(undefined4 *)(pWVar4 + 6);
    local_28 = *(undefined8 *)(pWVar4 + 8);
    uStack_20 = *(ulonglong *)(pWVar4 + 0xc);
    pWVar4[8] = L'\0';
    pWVar4[9] = L'\0';
    pWVar4[10] = L'\0';
    pWVar4[0xb] = L'\0';
    pWVar4[0xc] = L'\a';
    pWVar4[0xd] = L'\0';
    pWVar4[0xe] = L'\0';
    pWVar4[0xf] = L'\0';
    *pWVar4 = L'\0';
    uStack_174 = *(undefined4 *)(pWVar4 + 2);
  }
  uStack_170 = uStack_30;
  uStack_16c = uStack_2c;
  local_168 = local_28;
  uStack_160 = uStack_20;
  if (7 < local_140) {
    if ((0xfff < local_140 * 2 + 2) &&
       (0x1f < (local_158[0] - *(longlong *)(local_158[0] + -8)) - 8U)) {
      FUN_140035d28();
      goto LAB_14000b60c;
    }
    FUN_14002f180();
  }
  if (7 < DAT_14007ace8) {
    if ((0xfff < DAT_14007ace8 * 2 + 2) &&
       (0x1f < (DAT_14007acd0 - *(longlong *)(DAT_14007acd0 + -8)) - 8U)) {
      FUN_140035d28();
      FUN_140035d28();
      pcVar1 = (code *)swi(3);
      (*pcVar1)();
      return;
    }
    FUN_14002f180();
  }
  DAT_14007acd0 = CONCAT44(uStack_174,local_178);
  uRam000000014007acd8 = CONCAT44(uStack_16c,uStack_170);
  DAT_14007ace0 = local_168;
  DAT_14007ace8 = uStack_160;
  local_28 = 0;
  uStack_20 = 7;
  local_38 = local_38 & 0xffffffffffff0000;
  lpPathName = (LPCWSTR)FUN_14000a810(local_158);
  if (7 < *(ulonglong *)(lpPathName + 0xc)) {
    lpPathName = *(LPCWSTR *)lpPathName;
  }
  BVar2 = SetCurrentDirectoryW(lpPathName);
  if (7 < local_140) {
    if ((0xfff < local_140 * 2 + 2) &&
       (0x1f < (local_158[0] - *(longlong *)(local_158[0] + -8)) - 8U)) {
LAB_14000b60c:
      FUN_140035d28();
      pcVar1 = (code *)swi(3);
      (*pcVar1)();
      return;
    }
    FUN_14002f180();
  }
  if (BVar2 == 0) {
    FUN_140002e10(local_130,4,0x14006b258);
    if (local_b0 != '\0') {
      FUN_140012a30(local_130,0x14006b280);
    }
    DVar3 = GetLastError();
    if (local_b0 != '\0') {
      FUN_140014c60(local_130,DVar3);
    }
    FUN_140003090(local_130);
  }
  FUN_14002f160(local_18 ^ (ulonglong)auStack_198);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_14000b620 @ 14000b620