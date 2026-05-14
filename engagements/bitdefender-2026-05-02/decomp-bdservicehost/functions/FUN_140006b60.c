void FUN_140006b60(undefined1 *param_1,undefined8 param_2,undefined8 param_3)

{
  code *pcVar1;
  char cVar2;
  DWORD dwProcessId;
  BOOL BVar3;
  short *psVar4;
  longlong *plVar5;
  LPCWSTR ***ppppWVar6;
  wchar_t *pwVar7;
  longlong lVar8;
  undefined8 uVar9;
  undefined1 auStack_88 [32];
  undefined1 *local_68;
  HMODULE local_60;
  undefined **local_58;
  LPCWSTR **local_50 [3];
  ulonglong local_38;
  undefined8 local_30;
  undefined **local_28;
  ulonglong local_20;
  
  local_20 = DAT_14007a060 ^ (ulonglong)auStack_88;
  *param_1 = 0;
  *(undefined8 *)(param_1 + 8) = 0;
  local_60 = (HMODULE)((ulonglong)local_60 & 0xffffffff00000000);
  local_68 = param_1;
  dwProcessId = GetCurrentProcessId();
  BVar3 = ProcessIdToSessionId(dwProcessId,(DWORD *)&local_60);
  if ((BVar3 == 0) || ((int)local_60 != 0)) {
    local_60 = (HMODULE)0x0;
    local_58 = &PTR_vftable_14007ac70;
    FUN_140006180((longlong *)local_50,&local_60,param_3);
    if ((local_58[1] != DAT_14007ac78) || ((int)local_60 != 0)) {
      if (7 < local_38) {
        if ((0xfff < local_38 * 2 + 2) &&
           (0x1f < (ulonglong)((longlong)local_50[0] + (-8 - (longlong)local_50[0][-1]))))
        goto LAB_140006de6;
        FUN_14002f180();
      }
      goto LAB_140006db9;
    }
    ppppWVar6 = local_50;
    if (7 < local_38) {
      ppppWVar6 = (LPCWSTR ***)local_50[0];
    }
    cVar2 = FUN_140005250((LPCWSTR)ppppWVar6,(DWORD *)&local_60);
    if (7 < local_38) {
      if ((0xfff < local_38 * 2 + 2) &&
         (0x1f < (ulonglong)((longlong)local_50[0] + (-8 - (longlong)local_50[0][-1])))) {
LAB_140006de6:
        FUN_140035d28();
        goto LAB_140006dec;
      }
      FUN_14002f180();
    }
    if (cVar2 == '\0') goto LAB_140006db9;
    *param_1 = 1;
    local_30 = 0;
    local_28 = &PTR_vftable_14007ac70;
    FUN_1400067c0(local_50,&local_30,param_3);
    if ((int)local_30 != 0) {
LAB_140006c7b:
      if (7 < local_38) {
        if ((0xfff < local_38 * 2 + 2) &&
           (0x1f < (ulonglong)((longlong)local_50[0] + (-8 - (longlong)local_50[0][-1])))) {
LAB_140006dec:
          FUN_140035d28();
          pcVar1 = (code *)swi(3);
          (*pcVar1)();
          return;
        }
        FUN_14002f180();
      }
      goto LAB_140006dc2;
    }
    uVar9 = 7;
    pwVar7 = L"log.dll";
    ppppWVar6 = local_50;
    FUN_14000e630(ppppWVar6,(undefined8 *)L"log.dll",7);
    psVar4 = (short *)FUN_140006460(ppppWVar6,pwVar7,uVar9);
    if (7 < *(ulonglong *)(psVar4 + 0xc)) {
      psVar4 = *(short **)psVar4;
    }
    ppppWVar6 = local_50;
    if (7 < local_38) {
      ppppWVar6 = (LPCWSTR ***)local_50[0];
    }
    plVar5 = (longlong *)FUN_140005f40(&local_60,(LPCWSTR)ppppWVar6,psVar4,&local_30);
    if (*(HMODULE *)(param_1 + 8) != (HMODULE)0x0) {
      FreeLibrary(*(HMODULE *)(param_1 + 8));
      *(undefined8 *)(param_1 + 8) = 0;
    }
    lVar8 = *plVar5;
    *plVar5 = 0;
    *(longlong *)(param_1 + 8) = lVar8;
    if (local_60 != (HMODULE)0x0) {
      FreeLibrary(local_60);
      lVar8 = *(longlong *)(param_1 + 8);
    }
    if (lVar8 == 0) goto LAB_140006c7b;
    if (7 < local_38) {
      if ((0xfff < local_38 * 2 + 2) &&
         (0x1f < (ulonglong)((longlong)local_50[0] + (-8 - (longlong)local_50[0][-1]))))
      goto LAB_140006dec;
      FUN_14002f180();
    }
  }
  else {
LAB_140006db9:
    *param_1 = 0;
  }
  FUN_14000eb20();
LAB_140006dc2:
  FUN_14002f160(local_20 ^ (ulonglong)auStack_88);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_140006e00 @ 140006e00