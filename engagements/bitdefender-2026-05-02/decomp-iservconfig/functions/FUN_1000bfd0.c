void __fastcall FUN_1000bfd0(undefined4 *param_1,DWORD *param_2)

{
  code *pcVar1;
  DWORD DVar2;
  uint uVar3;
  DWORD DVar4;
  LPWSTR ***ppppWVar5;
  uint uStack_60;
  LPWSTR **local_44;
  undefined4 uStack_40;
  undefined4 uStack_3c;
  undefined4 uStack_38;
  uint local_34;
  uint uStack_30;
  uint local_2c;
  undefined1 *puStack_24;
  undefined1 *local_20;
  void *local_1c;
  undefined1 *puStack_18;
  undefined4 local_14;
  
  puStack_24 = &stack0xfffffffc;
  puStack_18 = &LAB_1004e55d;
  local_1c = ExceptionList;
  uStack_60 = DAT_10069054 ^ (uint)&stack0xfffffff0;
  local_20 = (undefined1 *)&uStack_60;
  ExceptionList = &local_1c;
  local_34 = 0;
  uStack_30 = 7;
  local_44 = (LPWSTR **)0x0;
  local_14 = 1;
  local_2c = uStack_60;
  FUN_1000f950(&local_44,0x7fff,0);
  ppppWVar5 = &local_44;
  if (7 < uStack_30) {
    ppppWVar5 = (LPWSTR ***)local_44;
  }
  DVar2 = GetModuleFileNameW((HMODULE)0x0,(LPWSTR)ppppWVar5,0x7fff);
  if (DVar2 == 0) {
    DVar2 = GetLastError();
    *param_2 = DVar2;
    param_2[1] = (DWORD)&PTR_vftable_10069ab8;
    *param_1 = 0;
    param_1[4] = 0;
    param_1[5] = 7;
    *(undefined2 *)param_1 = 0;
    if (uStack_30 < 8) goto LAB_1000c0ce;
    ppppWVar5 = (LPWSTR ***)local_44;
    if (0xfff < uStack_30 * 2 + 2) {
      ppppWVar5 = (LPWSTR ***)local_44[-1];
      uVar3 = (int)local_44 + (-4 - (int)ppppWVar5);
joined_r0x1000c136:
      if (0x1f < uVar3) {
        FUN_10032f7f();
        pcVar1 = (code *)swi(3);
        (*pcVar1)();
        return;
      }
    }
  }
  else {
    if ((DVar2 != 0x7fff) || (DVar4 = GetLastError(), DVar4 == 0)) {
      if (local_34 < DVar2) {
        FUN_1000f950(&local_44,DVar2 - local_34,0);
      }
      else {
        ppppWVar5 = &local_44;
        if (7 < uStack_30) {
          ppppWVar5 = (LPWSTR ***)local_44;
        }
        local_34 = DVar2;
        *(WCHAR *)((int)ppppWVar5 + DVar2 * 2) = L'\0';
      }
      FUN_1000ea80((uint *)&local_44);
      *param_2 = 0;
      param_2[1] = (DWORD)&PTR_vftable_10069aa8;
      *param_1 = 0;
      param_1[4] = 0;
      param_1[5] = 0;
      *param_1 = local_44;
      param_1[1] = uStack_40;
      param_1[2] = uStack_3c;
      param_1[3] = uStack_38;
      *(ulonglong *)(param_1 + 4) = CONCAT44(uStack_30,local_34);
      FUN_1000c1ec();
      return;
    }
    *param_2 = DVar4;
    param_2[1] = (DWORD)&PTR_vftable_10069ab8;
    *param_1 = 0;
    param_1[4] = 0;
    param_1[5] = 7;
    *(undefined2 *)param_1 = 0;
    if (uStack_30 < 8) goto LAB_1000c0ce;
    ppppWVar5 = (LPWSTR ***)local_44;
    if (0xfff < uStack_30 * 2 + 2) {
      ppppWVar5 = (LPWSTR ***)local_44[-1];
      uVar3 = (int)local_44 + (-4 - (int)ppppWVar5);
      goto joined_r0x1000c136;
    }
  }
  FUN_1002e346(ppppWVar5);
LAB_1000c0ce:
  FUN_1000c1ec();
  return;
}


// FUNCTION_END

// FUNCTION_START: Catch_All@1000c1a9 @ 1000c1a9