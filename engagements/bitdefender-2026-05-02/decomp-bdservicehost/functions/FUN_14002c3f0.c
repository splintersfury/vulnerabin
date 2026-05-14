void FUN_14002c3f0(void)

{
  undefined **ppuVar1;
  int iVar2;
  DWORD DVar3;
  HANDLE hObject;
  FARPROC pFVar4;
  LPCWSTR ***lpFileName;
  ulonglong uVar5;
  undefined4 uVar7;
  undefined8 uVar6;
  undefined4 extraout_XMM0_Dc;
  undefined4 uVar8;
  undefined4 extraout_XMM0_Dd;
  undefined4 uVar9;
  undefined1 auStackY_e8 [32];
  undefined8 local_a0 [5];
  undefined8 *local_78 [2];
  undefined8 local_68;
  undefined8 uStack_60;
  HMODULE local_48;
  LPCWSTR **local_40 [2];
  undefined8 local_30;
  ulonglong local_28;
  HANDLE local_20;
  ulonglong local_18;
  
  local_18 = DAT_14007a060 ^ (ulonglong)auStackY_e8;
  local_78[0] = (undefined8 *)0x0;
  iVar2 = SHGetKnownFolderPath(&DAT_14005bb20,0,0,local_78);
  if (iVar2 < 0) {
    FUN_140001ab0(&local_68,0x14006dde8);
                    /* WARNING: Subroutine does not return */
    _CxxThrowException(&local_68,(ThrowInfo *)&DAT_140077818);
  }
  local_30 = 0;
  local_28 = 7;
  local_40[0] = (LPCWSTR **)0x0;
  uVar5 = 0xffffffffffffffff;
  do {
    uVar5 = uVar5 + 1;
  } while (*(short *)((longlong)local_78[0] + uVar5 * 2) != 0);
  FUN_140010340((longlong *)local_40,local_78[0],uVar5);
  CoTaskMemFree(local_78[0]);
  FUN_14000e630(local_40,(undefined8 *)L"\\drivers\\bdelam.sys",0x13);
  lpFileName = local_40;
  if (7 < local_28) {
    lpFileName = (LPCWSTR ***)local_40[0];
  }
  hObject = CreateFileW((LPCWSTR)lpFileName,1,1,(LPSECURITY_ATTRIBUTES)0x0,3,0x80,(HANDLE)0x0);
  local_20 = hObject;
  if (hObject == (HANDLE)0xffffffffffffffff) {
    FUN_140001ab0(&local_68,0x14006de38);
                    /* WARNING: Subroutine does not return */
    _CxxThrowException(&local_68,(ThrowInfo *)&DAT_140077818);
  }
  local_48 = (HMODULE)0x0;
  FUN_1400038c0(&local_48,L"kernel32.dll");
  local_68 = 0;
  uStack_60 = (undefined **)0x0;
  pFVar4 = GetProcAddress(local_48,"InstallELAMCertificateInfo");
  if (pFVar4 == (FARPROC)0x0) {
    DVar3 = GetLastError();
    uStack_60._0_4_ = 0x4007ad08;
    uVar8 = (undefined4)uStack_60;
    local_68 = CONCAT44(local_68._4_4_,DVar3);
    uStack_60 = &PTR_vftable_14007ad08;
    uVar7 = local_68._4_4_;
  }
  else {
    uStack_60 = &PTR_vftable_14007ac70;
    ppuVar1 = uStack_60;
    uStack_60._0_4_ = 0x4007ac70;
    DVar3 = (DWORD)local_68;
    uVar7 = local_68._4_4_;
    uVar8 = (undefined4)uStack_60;
    uStack_60 = ppuVar1;
  }
  uVar9 = 1;
  uVar6 = CONCAT44(uVar7,DVar3);
  if ((uStack_60[1] == DAT_14007ac78) && (uVar6 = CONCAT44(uVar7,DVar3), DVar3 == 0)) {
    iVar2 = (*(code *)PTR__guard_dispatch_icall_14005b538)(hObject);
    if (iVar2 == 0) {
      FUN_140001ab0(&local_68,0x14006de78);
                    /* WARNING: Subroutine does not return */
      _CxxThrowException(&local_68,(ThrowInfo *)&DAT_140077818);
    }
    if (local_48 != (HMODULE)0x0) {
      FreeLibrary(local_48);
      local_48 = (HMODULE)0x0;
    }
    CloseHandle(hObject);
    if (7 < local_28) {
      if ((0xfff < local_28 * 2 + 2) &&
         (0x1f < (ulonglong)((longlong)local_40[0] + (-8 - (longlong)local_40[0][-1])))) {
        uVar6 = FUN_140035d28();
        uVar8 = extraout_XMM0_Dc;
        uVar9 = extraout_XMM0_Dd;
        goto LAB_14002c5f8;
      }
      FUN_14002f180();
    }
    FUN_14002f160(local_18 ^ (ulonglong)auStackY_e8);
    return;
  }
LAB_14002c5f8:
  local_68 = uVar6;
  uStack_60 = (undefined **)CONCAT44(uVar9,uVar8);
  FUN_140003760(local_a0,&local_68,(undefined8 *)"GetProcAddress failed");
                    /* WARNING: Subroutine does not return */
  _CxxThrowException(local_a0,(ThrowInfo *)&DAT_140077a60);
}


// FUNCTION_END

// FUNCTION_START: FUN_14002c690 @ 14002c690