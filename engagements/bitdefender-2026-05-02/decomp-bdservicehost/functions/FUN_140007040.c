void FUN_140007040(undefined8 *param_1,undefined8 *param_2)

{
  undefined8 uVar1;
  code *pcVar2;
  bool bVar3;
  bool bVar4;
  BOOL BVar5;
  DWORD DVar6;
  undefined1 (*pauVar7) [16];
  undefined8 *puVar8;
  FARPROC pFVar9;
  undefined **ppuVar10;
  LPCWSTR ****pppppWVar11;
  ulonglong uVar12;
  longlong lVar13;
  undefined4 uVar15;
  LPCWSTR ***ppppWVar14;
  undefined4 uVar16;
  undefined4 extraout_XMM0_Dc;
  undefined4 uVar17;
  undefined4 extraout_XMM0_Dd;
  undefined1 auStack_c8 [32];
  undefined8 local_a8 [2];
  undefined8 local_98;
  ulonglong local_90;
  undefined8 *local_80;
  HMODULE local_78 [2];
  LPCWSTR ***local_68;
  undefined8 uStack_60;
  undefined8 local_58;
  ulonglong uStack_50;
  LPCWSTR ***local_48;
  undefined8 uStack_40;
  undefined8 local_38;
  ulonglong uStack_30;
  ulonglong local_28;
  
  local_28 = DAT_14007a060 ^ (ulonglong)auStack_c8;
  local_78[0] = (HMODULE)((ulonglong)local_78[0] & 0xffffffff00000000);
  *param_1 = 0;
  param_1[1] = 0;
  param_1[2] = 0;
  param_1[3] = 0;
  param_1[4] = 0;
  param_1[5] = 0;
  param_1[6] = 0;
  param_1[7] = 0;
  param_1[8] = 0;
  param_1[9] = 0;
  param_1[10] = 0;
  param_1[0xb] = 0;
  param_1[0xc] = 0;
  param_1[0xd] = 0;
  param_1[0xe] = 0;
  param_1[0xf] = 0;
  param_1[0x10] = 0;
  param_1[0x11] = 0;
  local_80 = param_1;
  if (param_2 == (undefined8 *)0x0) {
    pauVar7 = FUN_140006670((undefined1 (*) [16])local_a8);
    bVar4 = false;
    bVar3 = true;
  }
  else {
    local_58 = 0;
    uStack_50 = 7;
    local_68 = (LPCWSTR ***)0x0;
    uVar12 = 0xffffffffffffffff;
    do {
      uVar12 = uVar12 + 1;
    } while (*(short *)((longlong)param_2 + uVar12 * 2) != 0);
    FUN_140010340((longlong *)&local_68,param_2,uVar12);
    pauVar7 = (undefined1 (*) [16])&local_68;
    bVar4 = true;
    bVar3 = false;
  }
  local_48 = (LPCWSTR ***)0x0;
  local_38 = 0;
  uStack_30 = 0;
  local_48 = (LPCWSTR ***)*(LPCWSTR *****)*pauVar7;
  uStack_40 = *(undefined8 *)(*pauVar7 + 8);
  local_38 = *(undefined8 *)pauVar7[1];
  uStack_30 = *(ulonglong *)(pauVar7[1] + 8);
  *(undefined8 *)pauVar7[1] = 0;
  *(undefined8 *)(pauVar7[1] + 8) = 7;
  *(undefined2 *)*pauVar7 = 0;
  if (bVar3) {
    if (7 < local_90) {
      if ((0xfff < local_90 * 2 + 2) &&
         (0x1f < (CONCAT62(local_a8[0]._2_6_,(undefined2)local_a8[0]) -
                 *(longlong *)(CONCAT62(local_a8[0]._2_6_,(undefined2)local_a8[0]) + -8)) - 8U)) {
        FUN_140035d28();
        goto LAB_140007aed;
      }
      FUN_14002f180();
    }
    local_98 = 0;
    local_90 = 7;
    local_a8[0]._0_2_ = 0;
  }
  if ((bVar4) && (7 < uStack_50)) {
    if ((0xfff < uStack_50 * 2 + 2) &&
       (0x1f < (ulonglong)((longlong)local_68 + (-8 - (longlong)local_68[-1])))) {
LAB_140007aed:
      FUN_140035d28();
      pcVar2 = (code *)swi(3);
      (*pcVar2)();
      return;
    }
    FUN_14002f180();
  }
  local_58 = 0;
  uStack_50 = 7;
  local_68 = (LPCWSTR ***)0x0;
  lVar13 = 8;
  FUN_140010340((longlong *)&local_68,(undefined8 *)L"bdch.dll",8);
  FUN_1400054f0((uint *)&local_48,(uint *)&local_68,lVar13);
  if (7 < uStack_50) {
    if ((0xfff < uStack_50 * 2 + 2) &&
       (0x1f < (ulonglong)((longlong)local_68 + (-8 - (longlong)local_68[-1])))) {
      FUN_140035d28();
      pcVar2 = (code *)swi(3);
      (*pcVar2)();
      return;
    }
    FUN_14002f180();
  }
  FUN_14000e750(&local_68,&local_48);
  pppppWVar11 = &local_68;
  if (7 < uStack_50) {
    pppppWVar11 = (LPCWSTR ****)local_68;
  }
  puVar8 = (undefined8 *)FUN_1400038c0(local_78,(LPCWSTR)pppppWVar11);
  if ((HMODULE)*param_1 != (HMODULE)0x0) {
    FreeLibrary((HMODULE)*param_1);
    *param_1 = 0;
  }
  uVar1 = *puVar8;
  *puVar8 = 0;
  *param_1 = uVar1;
  if (local_78[0] != (HMODULE)0x0) {
    FreeLibrary(local_78[0]);
    local_78[0] = (HMODULE)0x0;
  }
  if (uStack_50 < 8) {
LAB_1400072e5:
    pppppWVar11 = &local_48;
    if (7 < uStack_30) {
      pppppWVar11 = (LPCWSTR ****)local_48;
    }
    BVar5 = GetModuleHandleExW(1,(LPCWSTR)pppppWVar11,local_78);
    if (BVar5 != 0) {
      FreeLibrary(local_78[0]);
    }
    local_78[0] = (HMODULE)*param_1;
    local_68 = (LPCWSTR ***)0x0;
    uStack_60 = (undefined **)0x0;
    pFVar9 = GetProcAddress(local_78[0],"GetAPIVersion");
    if (pFVar9 == (FARPROC)0x0) {
      DVar6 = GetLastError();
      uStack_60._0_4_ = 0x4007ad08;
      uVar16 = (undefined4)uStack_60;
      uStack_60 = &PTR_vftable_14007ad08;
      ppuVar10 = uStack_60;
    }
    else {
      uStack_60._0_4_ = 0x4007ac70;
      ppuVar10 = &PTR_vftable_14007ac70;
      DVar6 = (DWORD)local_68;
      uVar16 = (undefined4)uStack_60;
    }
    if ((ppuVar10[1] != DAT_14007ac78) || (DVar6 != 0)) {
      local_68 = (LPCWSTR ***)CONCAT44(local_68._4_4_,DVar6);
      uStack_60._4_4_ = 1;
      uStack_60._0_4_ = uVar16;
      FUN_140003760(local_a8,&local_68,(undefined8 *)"GetProcAddress failed");
                    /* WARNING: Subroutine does not return */
      _CxxThrowException(local_a8,(ThrowInfo *)&DAT_140077a60);
    }
    param_1[1] = pFVar9;
    local_78[0] = (HMODULE)*param_1;
    local_68 = (LPCWSTR ***)0x0;
    uStack_60 = (undefined **)0x0;
    pFVar9 = GetProcAddress(local_78[0],"EnableBdch");
    if (pFVar9 == (FARPROC)0x0) {
      DVar6 = GetLastError();
      uStack_60._0_4_ = 0x4007ad08;
      uVar16 = (undefined4)uStack_60;
      uStack_60 = &PTR_vftable_14007ad08;
      ppuVar10 = uStack_60;
    }
    else {
      uStack_60._0_4_ = 0x4007ac70;
      ppuVar10 = &PTR_vftable_14007ac70;
      DVar6 = (DWORD)local_68;
      uVar16 = (undefined4)uStack_60;
    }
    if ((ppuVar10[1] != DAT_14007ac78) || (DVar6 != 0)) {
      local_68 = (LPCWSTR ***)CONCAT44(local_68._4_4_,DVar6);
      uStack_60._4_4_ = 1;
      uStack_60._0_4_ = uVar16;
      FUN_140003760(local_a8,&local_68,(undefined8 *)"GetProcAddress failed");
                    /* WARNING: Subroutine does not return */
      _CxxThrowException(local_a8,(ThrowInfo *)&DAT_140077a60);
    }
    param_1[2] = pFVar9;
    local_78[0] = (HMODULE)*param_1;
    local_68 = (LPCWSTR ***)0x0;
    uStack_60 = (undefined **)0x0;
    pFVar9 = GetProcAddress(local_78[0],"UninitBdch");
    if (pFVar9 == (FARPROC)0x0) {
      DVar6 = GetLastError();
      uStack_60._0_4_ = 0x4007ad08;
      uVar16 = (undefined4)uStack_60;
      uStack_60 = &PTR_vftable_14007ad08;
      ppuVar10 = uStack_60;
    }
    else {
      uStack_60._0_4_ = 0x4007ac70;
      ppuVar10 = &PTR_vftable_14007ac70;
      DVar6 = (DWORD)local_68;
      uVar16 = (undefined4)uStack_60;
    }
    if ((ppuVar10[1] != DAT_14007ac78) || (DVar6 != 0)) {
      local_68 = (LPCWSTR ***)CONCAT44(local_68._4_4_,DVar6);
      uStack_60._4_4_ = 1;
      uStack_60._0_4_ = uVar16;
      FUN_140003760(local_a8,&local_68,(undefined8 *)"GetProcAddress failed");
                    /* WARNING: Subroutine does not return */
      _CxxThrowException(local_a8,(ThrowInfo *)&DAT_140077a60);
    }
    param_1[3] = pFVar9;
    local_78[0] = (HMODULE)*param_1;
    local_68 = (LPCWSTR ***)0x0;
    uStack_60 = (undefined **)0x0;
    pFVar9 = GetProcAddress(local_78[0],"SetWerText");
    if (pFVar9 == (FARPROC)0x0) {
      DVar6 = GetLastError();
      uStack_60._0_4_ = 0x4007ad08;
      uVar16 = (undefined4)uStack_60;
      uStack_60 = &PTR_vftable_14007ad08;
      ppuVar10 = uStack_60;
    }
    else {
      uStack_60._0_4_ = 0x4007ac70;
      ppuVar10 = &PTR_vftable_14007ac70;
      DVar6 = (DWORD)local_68;
      uVar16 = (undefined4)uStack_60;
    }
    if ((ppuVar10[1] != DAT_14007ac78) || (DVar6 != 0)) {
      local_68 = (LPCWSTR ***)CONCAT44(local_68._4_4_,DVar6);
      uStack_60._4_4_ = 1;
      uStack_60._0_4_ = uVar16;
      FUN_140003760(local_a8,&local_68,(undefined8 *)"GetProcAddress failed");
                    /* WARNING: Subroutine does not return */
      _CxxThrowException(local_a8,(ThrowInfo *)&DAT_140077a60);
    }
    param_1[4] = pFVar9;
    local_78[0] = (HMODULE)*param_1;
    local_68 = (LPCWSTR ***)0x0;
    uStack_60 = (undefined **)0x0;
    pFVar9 = GetProcAddress(local_78[0],"AddExtraFilesToDump");
    if (pFVar9 == (FARPROC)0x0) {
      DVar6 = GetLastError();
      uStack_60._0_4_ = 0x4007ad08;
      uVar16 = (undefined4)uStack_60;
      uStack_60 = &PTR_vftable_14007ad08;
      ppuVar10 = uStack_60;
    }
    else {
      uStack_60._0_4_ = 0x4007ac70;
      ppuVar10 = &PTR_vftable_14007ac70;
      DVar6 = (DWORD)local_68;
      uVar16 = (undefined4)uStack_60;
    }
    if ((ppuVar10[1] != DAT_14007ac78) || (DVar6 != 0)) {
      local_68 = (LPCWSTR ***)CONCAT44(local_68._4_4_,DVar6);
      uStack_60._4_4_ = 1;
      uStack_60._0_4_ = uVar16;
      FUN_140003760(local_a8,&local_68,(undefined8 *)"GetProcAddress failed");
                    /* WARNING: Subroutine does not return */
      _CxxThrowException(local_a8,(ThrowInfo *)&DAT_140077a60);
    }
    param_1[5] = pFVar9;
    local_78[0] = (HMODULE)*param_1;
    local_68 = (LPCWSTR ***)0x0;
    uStack_60 = (undefined **)0x0;
    pFVar9 = GetProcAddress(local_78[0],"GetSettings");
    if (pFVar9 == (FARPROC)0x0) {
      DVar6 = GetLastError();
      uStack_60._0_4_ = 0x4007ad08;
      uVar16 = (undefined4)uStack_60;
      uStack_60 = &PTR_vftable_14007ad08;
      ppuVar10 = uStack_60;
    }
    else {
      uStack_60._0_4_ = 0x4007ac70;
      ppuVar10 = &PTR_vftable_14007ac70;
      DVar6 = (DWORD)local_68;
      uVar16 = (undefined4)uStack_60;
    }
    if ((ppuVar10[1] != DAT_14007ac78) || (DVar6 != 0)) {
      local_68 = (LPCWSTR ***)CONCAT44(local_68._4_4_,DVar6);
      uStack_60._4_4_ = 1;
      uStack_60._0_4_ = uVar16;
      FUN_140003760(local_a8,&local_68,(undefined8 *)"GetProcAddress failed");
                    /* WARNING: Subroutine does not return */
      _CxxThrowException(local_a8,(ThrowInfo *)&DAT_140077a60);
    }
    param_1[6] = pFVar9;
    local_78[0] = (HMODULE)*param_1;
    local_68 = (LPCWSTR ***)0x0;
    uStack_60 = (undefined **)0x0;
    pFVar9 = GetProcAddress(local_78[0],"SetSettings");
    if (pFVar9 == (FARPROC)0x0) {
      DVar6 = GetLastError();
      uStack_60._0_4_ = 0x4007ad08;
      uVar16 = (undefined4)uStack_60;
      uStack_60 = &PTR_vftable_14007ad08;
      ppuVar10 = uStack_60;
    }
    else {
      uStack_60._0_4_ = 0x4007ac70;
      ppuVar10 = &PTR_vftable_14007ac70;
      DVar6 = (DWORD)local_68;
      uVar16 = (undefined4)uStack_60;
    }
    if ((ppuVar10[1] != DAT_14007ac78) || (DVar6 != 0)) {
      local_68 = (LPCWSTR ***)CONCAT44(local_68._4_4_,DVar6);
      uStack_60._4_4_ = 1;
      uStack_60._0_4_ = uVar16;
      FUN_140003760(local_a8,&local_68,(undefined8 *)"GetProcAddress failed");
                    /* WARNING: Subroutine does not return */
      _CxxThrowException(local_a8,(ThrowInfo *)&DAT_140077a60);
    }
    param_1[7] = pFVar9;
    local_78[0] = (HMODULE)*param_1;
    local_68 = (LPCWSTR ***)0x0;
    uStack_60 = (undefined **)0x0;
    pFVar9 = GetProcAddress(local_78[0],"SyncSettings");
    if (pFVar9 == (FARPROC)0x0) {
      DVar6 = GetLastError();
      uStack_60._0_4_ = 0x4007ad08;
      uVar16 = (undefined4)uStack_60;
      uStack_60 = &PTR_vftable_14007ad08;
      ppuVar10 = uStack_60;
    }
    else {
      uStack_60._0_4_ = 0x4007ac70;
      ppuVar10 = &PTR_vftable_14007ac70;
      DVar6 = (DWORD)local_68;
      uVar16 = (undefined4)uStack_60;
    }
    if ((ppuVar10[1] != DAT_14007ac78) || (DVar6 != 0)) {
      local_68 = (LPCWSTR ***)CONCAT44(local_68._4_4_,DVar6);
      uStack_60._4_4_ = 1;
      uStack_60._0_4_ = uVar16;
      FUN_140003760(local_a8,&local_68,(undefined8 *)"GetProcAddress failed");
                    /* WARNING: Subroutine does not return */
      _CxxThrowException(local_a8,(ThrowInfo *)&DAT_140077a60);
    }
    param_1[8] = pFVar9;
    local_78[0] = (HMODULE)*param_1;
    local_68 = (LPCWSTR ***)0x0;
    uStack_60 = (undefined **)0x0;
    pFVar9 = GetProcAddress(local_78[0],"ListDumps");
    if (pFVar9 == (FARPROC)0x0) {
      DVar6 = GetLastError();
      uStack_60._0_4_ = 0x4007ad08;
      uVar16 = (undefined4)uStack_60;
      uStack_60 = &PTR_vftable_14007ad08;
      ppuVar10 = uStack_60;
    }
    else {
      uStack_60._0_4_ = 0x4007ac70;
      ppuVar10 = &PTR_vftable_14007ac70;
      DVar6 = (DWORD)local_68;
      uVar16 = (undefined4)uStack_60;
    }
    if ((ppuVar10[1] != DAT_14007ac78) || (DVar6 != 0)) {
      local_68 = (LPCWSTR ***)CONCAT44(local_68._4_4_,DVar6);
      uStack_60._4_4_ = 1;
      uStack_60._0_4_ = uVar16;
      FUN_140003760(local_a8,&local_68,(undefined8 *)"GetProcAddress failed");
                    /* WARNING: Subroutine does not return */
      _CxxThrowException(local_a8,(ThrowInfo *)&DAT_140077a60);
    }
    param_1[9] = pFVar9;
    local_78[0] = (HMODULE)*param_1;
    local_68 = (LPCWSTR ***)0x0;
    uStack_60 = (undefined **)0x0;
    pFVar9 = GetProcAddress(local_78[0],"FreeDumpResponse");
    if (pFVar9 == (FARPROC)0x0) {
      DVar6 = GetLastError();
      uStack_60._0_4_ = 0x4007ad08;
      uVar16 = (undefined4)uStack_60;
      uStack_60 = &PTR_vftable_14007ad08;
      ppuVar10 = uStack_60;
    }
    else {
      uStack_60._0_4_ = 0x4007ac70;
      ppuVar10 = &PTR_vftable_14007ac70;
      DVar6 = (DWORD)local_68;
      uVar16 = (undefined4)uStack_60;
    }
    if ((ppuVar10[1] != DAT_14007ac78) || (DVar6 != 0)) {
      local_68 = (LPCWSTR ***)CONCAT44(local_68._4_4_,DVar6);
      uStack_60._4_4_ = 1;
      uStack_60._0_4_ = uVar16;
      FUN_140003760(local_a8,&local_68,(undefined8 *)"GetProcAddress failed");
                    /* WARNING: Subroutine does not return */
      _CxxThrowException(local_a8,(ThrowInfo *)&DAT_140077a60);
    }
    param_1[10] = pFVar9;
    local_78[0] = (HMODULE)*param_1;
    local_68 = (LPCWSTR ***)0x0;
    uStack_60 = (undefined **)0x0;
    pFVar9 = GetProcAddress(local_78[0],"SubmitDump");
    if (pFVar9 == (FARPROC)0x0) {
      DVar6 = GetLastError();
      uStack_60._0_4_ = 0x4007ad08;
      uVar16 = (undefined4)uStack_60;
      uStack_60 = &PTR_vftable_14007ad08;
      ppuVar10 = uStack_60;
    }
    else {
      uStack_60._0_4_ = 0x4007ac70;
      ppuVar10 = &PTR_vftable_14007ac70;
      DVar6 = (DWORD)local_68;
      uVar16 = (undefined4)uStack_60;
    }
    if ((ppuVar10[1] != DAT_14007ac78) || (DVar6 != 0)) {
      local_68 = (LPCWSTR ***)CONCAT44(local_68._4_4_,DVar6);
      uStack_60._4_4_ = 1;
      uStack_60._0_4_ = uVar16;
      FUN_140003760(local_a8,&local_68,(undefined8 *)"GetProcAddress failed");
                    /* WARNING: Subroutine does not return */
      _CxxThrowException(local_a8,(ThrowInfo *)&DAT_140077a60);
    }
    param_1[0xb] = pFVar9;
    local_78[0] = (HMODULE)*param_1;
    local_68 = (LPCWSTR ***)0x0;
    uStack_60 = (undefined **)0x0;
    pFVar9 = GetProcAddress(local_78[0],"DeleteDump");
    if (pFVar9 == (FARPROC)0x0) {
      DVar6 = GetLastError();
      uStack_60._0_4_ = 0x4007ad08;
      uVar16 = (undefined4)uStack_60;
      uStack_60 = &PTR_vftable_14007ad08;
      ppuVar10 = uStack_60;
    }
    else {
      uStack_60._0_4_ = 0x4007ac70;
      ppuVar10 = &PTR_vftable_14007ac70;
      DVar6 = (DWORD)local_68;
      uVar16 = (undefined4)uStack_60;
    }
    if ((ppuVar10[1] != DAT_14007ac78) || (DVar6 != 0)) {
      local_68 = (LPCWSTR ***)CONCAT44(local_68._4_4_,DVar6);
      uStack_60._4_4_ = 1;
      uStack_60._0_4_ = uVar16;
      FUN_140003760(local_a8,&local_68,(undefined8 *)"GetProcAddress failed");
                    /* WARNING: Subroutine does not return */
      _CxxThrowException(local_a8,(ThrowInfo *)&DAT_140077a60);
    }
    param_1[0xc] = pFVar9;
    local_78[0] = (HMODULE)*param_1;
    local_68 = (LPCWSTR ***)0x0;
    uStack_60 = (undefined **)0x0;
    pFVar9 = GetProcAddress(local_78[0],"SignalHandler");
    if (pFVar9 == (FARPROC)0x0) {
      DVar6 = GetLastError();
      uStack_60._0_4_ = 0x4007ad08;
      uVar16 = (undefined4)uStack_60;
      uStack_60 = &PTR_vftable_14007ad08;
      ppuVar10 = uStack_60;
    }
    else {
      uStack_60._0_4_ = 0x4007ac70;
      ppuVar10 = &PTR_vftable_14007ac70;
      DVar6 = (DWORD)local_68;
      uVar16 = (undefined4)uStack_60;
    }
    if ((ppuVar10[1] != DAT_14007ac78) || (DVar6 != 0)) {
      local_68 = (LPCWSTR ***)CONCAT44(local_68._4_4_,DVar6);
      uStack_60._4_4_ = 1;
      uStack_60._0_4_ = uVar16;
      FUN_140003760(local_a8,&local_68,(undefined8 *)"GetProcAddress failed");
                    /* WARNING: Subroutine does not return */
      _CxxThrowException(local_a8,(ThrowInfo *)&DAT_140077a60);
    }
    param_1[0xd] = pFVar9;
    local_78[0] = (HMODULE)*param_1;
    local_68 = (LPCWSTR ***)0x0;
    uStack_60 = (undefined **)0x0;
    pFVar9 = GetProcAddress(local_78[0],"GetSettingsFromFile");
    if (pFVar9 == (FARPROC)0x0) {
      DVar6 = GetLastError();
      uStack_60._0_4_ = 0x4007ad08;
      uVar16 = (undefined4)uStack_60;
      uStack_60 = &PTR_vftable_14007ad08;
      ppuVar10 = uStack_60;
    }
    else {
      uStack_60._0_4_ = 0x4007ac70;
      ppuVar10 = &PTR_vftable_14007ac70;
      DVar6 = (DWORD)local_68;
      uVar16 = (undefined4)uStack_60;
    }
    if ((ppuVar10[1] != DAT_14007ac78) || (DVar6 != 0)) {
      local_68 = (LPCWSTR ***)CONCAT44(local_68._4_4_,DVar6);
      uStack_60._4_4_ = 1;
      uStack_60._0_4_ = uVar16;
      FUN_140003760(local_a8,&local_68,(undefined8 *)"GetProcAddress failed");
                    /* WARNING: Subroutine does not return */
      _CxxThrowException(local_a8,(ThrowInfo *)&DAT_140077a60);
    }
    param_1[0xe] = pFVar9;
    local_78[0] = (HMODULE)*param_1;
    local_68 = (LPCWSTR ***)0x0;
    uStack_60 = (undefined **)0x0;
    pFVar9 = GetProcAddress(local_78[0],"SaveSettingsToFile");
    if (pFVar9 == (FARPROC)0x0) {
      DVar6 = GetLastError();
      uStack_60._0_4_ = 0x4007ad08;
      uVar16 = (undefined4)uStack_60;
      uStack_60 = &PTR_vftable_14007ad08;
      ppuVar10 = uStack_60;
    }
    else {
      uStack_60._0_4_ = 0x4007ac70;
      ppuVar10 = &PTR_vftable_14007ac70;
      DVar6 = (DWORD)local_68;
      uVar16 = (undefined4)uStack_60;
    }
    if ((ppuVar10[1] != DAT_14007ac78) || (DVar6 != 0)) {
      local_68 = (LPCWSTR ***)CONCAT44(local_68._4_4_,DVar6);
      uStack_60._4_4_ = 1;
      uStack_60._0_4_ = uVar16;
      FUN_140003760(local_a8,&local_68,(undefined8 *)"GetProcAddress failed");
                    /* WARNING: Subroutine does not return */
      _CxxThrowException(local_a8,(ThrowInfo *)&DAT_140077a60);
    }
    param_1[0xf] = pFVar9;
    local_78[0] = (HMODULE)*param_1;
    local_68 = (LPCWSTR ***)0x0;
    uStack_60 = (undefined **)0x0;
    pFVar9 = GetProcAddress(local_78[0],"ConvertOldConfigToNewConfig");
    if (pFVar9 == (FARPROC)0x0) {
      DVar6 = GetLastError();
      uStack_60._0_4_ = 0x4007ad08;
      uVar16 = (undefined4)uStack_60;
      uStack_60 = &PTR_vftable_14007ad08;
      ppuVar10 = uStack_60;
    }
    else {
      uStack_60._0_4_ = 0x4007ac70;
      ppuVar10 = &PTR_vftable_14007ac70;
      DVar6 = (DWORD)local_68;
      uVar16 = (undefined4)uStack_60;
    }
    if ((ppuVar10[1] != DAT_14007ac78) || (DVar6 != 0)) {
      local_68 = (LPCWSTR ***)CONCAT44(local_68._4_4_,DVar6);
      uStack_60._4_4_ = 1;
      uStack_60._0_4_ = uVar16;
      FUN_140003760(local_a8,&local_68,(undefined8 *)"GetProcAddress failed");
                    /* WARNING: Subroutine does not return */
      _CxxThrowException(local_a8,(ThrowInfo *)&DAT_140077a60);
    }
    param_1[0x10] = pFVar9;
    local_78[0] = (HMODULE)*param_1;
    local_68 = (LPCWSTR ***)0x0;
    uStack_60 = (undefined **)0x0;
    pFVar9 = GetProcAddress(local_78[0],"ReleaseBdchSettings");
    if (pFVar9 == (FARPROC)0x0) {
      DVar6 = GetLastError();
      uStack_60._0_4_ = 0x4007ad08;
      uVar16 = (undefined4)uStack_60;
      local_68 = (LPCWSTR ***)CONCAT44(local_68._4_4_,DVar6);
      uStack_60 = &PTR_vftable_14007ad08;
      uVar15 = local_68._4_4_;
    }
    else {
      uStack_60 = &PTR_vftable_14007ac70;
      ppuVar10 = uStack_60;
      uStack_60._0_4_ = 0x4007ac70;
      DVar6 = (DWORD)local_68;
      uVar15 = local_68._4_4_;
      uVar16 = (undefined4)uStack_60;
      uStack_60 = ppuVar10;
    }
    uVar17 = 1;
    ppppWVar14 = (LPCWSTR ***)CONCAT44(uVar15,DVar6);
    if ((uStack_60[1] != DAT_14007ac78) ||
       (ppppWVar14 = (LPCWSTR ***)CONCAT44(uVar15,DVar6), DVar6 != 0)) goto LAB_140007b05;
    param_1[0x11] = pFVar9;
    if (uStack_30 < 8) {
LAB_140007a6c:
      FUN_14002f160(local_28 ^ (ulonglong)auStack_c8);
      return;
    }
    if ((uStack_30 * 2 + 2 < 0x1000) ||
       ((ulonglong)((longlong)local_48 + (-8 - (longlong)local_48[-1])) < 0x20)) {
      FUN_14002f180();
      goto LAB_140007a6c;
    }
  }
  else {
    if ((uStack_50 * 2 + 2 < 0x1000) ||
       ((ulonglong)((longlong)local_68 + (-8 - (longlong)local_68[-1])) < 0x20)) {
      FUN_14002f180();
      goto LAB_1400072e5;
    }
    FUN_140035d28();
  }
  ppppWVar14 = (LPCWSTR ***)FUN_140035d28();
  uVar16 = extraout_XMM0_Dc;
  uVar17 = extraout_XMM0_Dd;
LAB_140007b05:
  local_68 = ppppWVar14;
  uStack_60._4_4_ = uVar17;
  uStack_60._0_4_ = uVar16;
  FUN_140003760(local_a8,&local_68,(undefined8 *)"GetProcAddress failed");
                    /* WARNING: Subroutine does not return */
  _CxxThrowException(local_a8,(ThrowInfo *)&DAT_140077a60);
}


// FUNCTION_END

// FUNCTION_START: FUN_140007d80 @ 140007d80