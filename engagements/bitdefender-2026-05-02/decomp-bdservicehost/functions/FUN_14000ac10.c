void FUN_14000ac10(uint param_1,longlong param_2)

{
  code *pcVar1;
  int iVar2;
  uint uVar3;
  longlong *plVar4;
  undefined8 *puVar5;
  wchar_t *pwVar6;
  wchar_t *pwVar7;
  undefined1 auStack_3c8 [32];
  longlong local_3a8;
  longlong local_3a0;
  undefined2 local_398;
  undefined6 uStack_396;
  undefined8 local_388;
  wchar_t *local_380;
  longlong local_368 [16];
  char local_2e8;
  longlong local_178 [2];
  undefined **local_168;
  HANDLE pvStack_160;
  undefined8 local_158;
  HMODULE pHStack_150;
  longlong local_148;
  longlong lStack_140;
  undefined8 local_138;
  undefined8 uStack_130;
  longlong local_128 [2];
  longlong local_118;
  undefined1 local_110 [232];
  ulonglong local_28;
  
  local_28 = DAT_14007a060 ^ (ulonglong)auStack_3c8;
  local_178[0] = 0;
  local_3a0 = param_2;
  FUN_140031e00((undefined1 (*) [16])local_128,0,0xf8);
  FUN_14000d640(local_128);
  plVar4 = FUN_140012a30(&local_118,0x14006b098);
  puVar5 = &DAT_14007acd0;
  if (7 < DAT_14007ace8) {
    puVar5 = DAT_14007acd0;
  }
  plVar4 = FUN_1400147e0(plVar4,puVar5,DAT_14007ace0);
  FUN_140012a30(plVar4,0x14006b090);
  plVar4 = FUN_140012a30(&local_118,0x14006b098);
  puVar5 = &DAT_14007acb0;
  if (7 < DAT_14007acc8) {
    puVar5 = DAT_14007acb0;
  }
  plVar4 = FUN_1400147e0(plVar4,puVar5,DAT_14007acc0);
  FUN_140012a30(plVar4,0x14006b090);
  FUN_140012a30(&local_118,0x14006b0a0);
  pwVar7 = DAT_14007acf0;
  FUN_1400100a0((longlong)local_110,(longlong *)&local_398);
  puVar5 = (undefined8 *)&local_398;
  plVar4 = (longlong *)FUN_14000a900(&local_3a8,puVar5,(undefined8 *)pwVar7);
  if (local_178 != plVar4) {
    local_178[0] = *plVar4;
    *plVar4 = 0;
  }
  if (local_3a8 != 0) {
    FUN_140008b00(local_3a8,puVar5,pwVar7);
    FUN_14002f180();
  }
  pwVar6 = local_380;
  if ((wchar_t *)0x7 < local_380) {
    pwVar6 = (wchar_t *)((longlong)local_380 * 2 + 2);
    if (((wchar_t *)0xfff < pwVar6) &&
       (pwVar6 = (wchar_t *)((longlong)local_380 * 2 + 0x29),
       0x1f < (CONCAT62(uStack_396,local_398) - *(longlong *)(CONCAT62(uStack_396,local_398) + -8))
              - 8U)) {
      FUN_140035d28();
      pcVar1 = (code *)swi(3);
      (*pcVar1)();
      return;
    }
    FUN_14002f180();
  }
  local_388 = 0;
  local_380 = (wchar_t *)0x7;
  local_398 = 0;
  FUN_140004010(local_128);
  if (1 < param_1) {
    uVar3 = FUN_140008d90(*(undefined1 (**) [16])(param_2 + 8));
    pwVar7 = L"check_intentional_crash";
    pwVar6 = (wchar_t *)0x10;
    FUN_140002e10(local_368,0x10,0x14006b060);
    if (local_2e8 != '\0') {
      pwVar6 = L"crash interval: ";
      FUN_140012a30(local_368,0x14006b038);
      if (local_2e8 != '\0') {
        pwVar6 = (wchar_t *)(ulonglong)uVar3;
        FUN_14000e200(local_368,uVar3);
      }
    }
    FUN_140003090(local_368);
    FUN_140008fd0(uVar3);
  }
  local_168 = (undefined **)0x0;
  pvStack_160 = (HANDLE)0x0;
  local_158 = 0;
  pHStack_150 = (HMODULE)0x0;
  local_148 = 0;
  lStack_140 = 0;
  local_138 = 0;
  uStack_130 = 0;
  FUN_140015360(&local_168);
  DAT_14007acf8 = &local_168;
  DAT_14007ad00 = 1;
  FUN_1400159d0((longlong *)&local_168);
  DAT_14007ad00 = 0;
  local_168 = service::vftable;
  if (pvStack_160 != (HANDLE)0x0) {
    CloseHandle(pvStack_160);
    pvStack_160 = (HANDLE)0x0;
  }
  if ((lStack_140 != 0) && (local_148 != 0)) {
    (*(code *)PTR__guard_dispatch_icall_14005b538)();
    lStack_140 = 0;
    local_148 = 0;
  }
  local_138 = 0;
  LOCK();
  UNLOCK();
  iVar2 = (int)uStack_130;
  while (uStack_130._0_4_ = iVar2 + -1, -1 < iVar2 + -1) {
    FUN_140011e70();
    LOCK();
    UNLOCK();
    iVar2 = (int)uStack_130;
  }
  LOCK();
  uStack_130 = CONCAT44(uStack_130._4_4_,iVar2);
  UNLOCK();
  if (pHStack_150 != (HMODULE)0x0) {
    FreeLibrary(pHStack_150);
  }
  if (local_178[0] != 0) {
    FUN_140008b00(local_178[0],pwVar6,pwVar7);
    FUN_14002f180();
  }
  FUN_14002f160(local_28 ^ (ulonglong)auStack_3c8);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_14000afb0 @ 14000afb0