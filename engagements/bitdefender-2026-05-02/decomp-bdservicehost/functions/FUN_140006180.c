void FUN_140006180(longlong *param_1,undefined8 *param_2,undefined8 param_3)

{
  code *pcVar1;
  ulonglong uVar2;
  DWORD DVar3;
  LPWSTR ***ppppWVar4;
  ulonglong uVar5;
  ulonglong uVar6;
  ulonglong uVar7;
  LPWSTR pWVar8;
  undefined1 auStackY_98 [32];
  undefined4 uStack_64;
  LPWSTR **local_48;
  longlong lStack_40;
  ulonglong local_38;
  ulonglong uStack_30;
  ulonglong local_28;
  
  local_28 = DAT_14007a060 ^ (ulonglong)auStackY_98;
  local_38 = 0;
  uStack_30 = 7;
  local_48 = (LPWSTR **)0x0;
  FUN_140013620(&local_48,0x7fff,param_3,0x7fff,0);
  ppppWVar4 = &local_48;
  if (7 < uStack_30) {
    ppppWVar4 = (LPWSTR ***)local_48;
  }
  DVar3 = GetModuleFileNameW((HMODULE)0x0,(LPWSTR)ppppWVar4,0x7fff);
  uVar7 = (ulonglong)DVar3;
  if (DVar3 == 0) {
    DVar3 = GetLastError();
    *param_2 = CONCAT44(uStack_64,DVar3);
    param_2[1] = &PTR_vftable_14007ad08;
    *param_1 = 0;
    param_1[2] = 0;
    param_1[3] = 7;
    *(undefined2 *)param_1 = 0;
    if (7 < uStack_30) {
      if ((0xfff < uStack_30 * 2 + 2) &&
         (0x1f < (ulonglong)((longlong)local_48 + (-8 - (longlong)local_48[-1])))) {
LAB_140006451:
        FUN_140035d28();
        pcVar1 = (code *)swi(3);
        (*pcVar1)();
        return;
      }
      FUN_14002f180();
    }
    local_38 = 0;
    uStack_30 = 7;
    local_48 = (LPWSTR **)((ulonglong)local_48 & 0xffffffffffff0000);
  }
  else if ((DVar3 == 0x7fff) && (DVar3 = GetLastError(), DVar3 != 0)) {
    *param_2 = CONCAT44(uStack_64,DVar3);
    param_2[1] = &PTR_vftable_14007ad08;
    *param_1 = 0;
    param_1[2] = 0;
    param_1[3] = 7;
    *(undefined2 *)param_1 = 0;
    if (7 < uStack_30) {
      if ((0xfff < uStack_30 * 2 + 2) &&
         (0x1f < (ulonglong)((longlong)local_48 + (-8 - (longlong)local_48[-1]))))
      goto LAB_140006451;
      FUN_14002f180();
    }
    local_38 = 0;
    uStack_30 = 7;
    local_48 = (LPWSTR **)((ulonglong)local_48 & 0xffffffffffff0000);
  }
  else {
    uVar2 = local_38;
    if (local_38 < uVar7) {
      uVar6 = uVar7 - local_38;
      if (uStack_30 - local_38 < uVar6) {
        FUN_140013620(&local_48,uVar6,local_38,uVar6,0);
      }
      else {
        ppppWVar4 = &local_48;
        if (7 < uStack_30) {
          ppppWVar4 = (LPWSTR ***)local_48;
        }
        pWVar8 = (LPWSTR)((longlong)ppppWVar4 + local_38 * 2);
        uVar5 = uVar6;
        local_38 = uVar7;
        if (uVar6 != 0) {
          for (; uVar5 != 0; uVar5 = uVar5 - 1) {
            *pWVar8 = L'\0';
            pWVar8 = pWVar8 + 1;
          }
        }
        *(WCHAR *)((longlong)ppppWVar4 + (uVar2 + uVar6) * 2) = L'\0';
      }
    }
    else {
      ppppWVar4 = &local_48;
      if (7 < uStack_30) {
        ppppWVar4 = (LPWSTR ***)local_48;
      }
      local_38 = uVar7;
      *(WCHAR *)((longlong)ppppWVar4 + uVar7 * 2) = L'\0';
    }
    FUN_14000e4b0((longlong *)&local_48);
    *(undefined4 *)param_2 = 0;
    param_2[1] = &PTR_vftable_14007ac70;
    *param_1 = (longlong)local_48;
    param_1[1] = lStack_40;
    param_1[2] = local_38;
    param_1[3] = uStack_30;
  }
  FUN_14002f160(local_28 ^ (ulonglong)auStackY_98);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_140006460 @ 140006460

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */