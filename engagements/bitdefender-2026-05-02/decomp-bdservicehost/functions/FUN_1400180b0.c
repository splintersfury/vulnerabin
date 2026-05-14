void FUN_1400180b0(undefined8 *param_1,undefined8 param_2,undefined8 param_3,LPCSTR param_4)

{
  ulonglong uVar1;
  uint cchWideChar;
  DWORD DVar2;
  int iVar3;
  LPWSTR ***ppppWVar4;
  ulonglong uVar5;
  ulonglong uVar6;
  ulonglong uVar7;
  LPWSTR pWVar8;
  undefined1 auStackY_a8 [32];
  undefined8 *local_78;
  undefined **ppuStack_70;
  undefined8 local_68 [5];
  LPWSTR **local_40;
  undefined8 uStack_38;
  ulonglong local_30;
  ulonglong uStack_28;
  ulonglong local_20;
  
  local_20 = DAT_14007a060 ^ (ulonglong)auStackY_a8;
  local_78 = param_1;
  cchWideChar = MultiByteToWideChar(0xfde9,0,param_4,-1,(LPWSTR)0x0,0);
  if ((int)cchWideChar < 0) {
    DVar2 = GetLastError();
    local_78 = (undefined8 *)CONCAT44(local_78._4_4_,DVar2);
    ppuStack_70 = &PTR_vftable_14007ad08;
    cchWideChar = 0;
  }
  else if ((cchWideChar == 0) && (DVar2 = GetLastError(), DVar2 != 0)) {
    local_78 = (undefined8 *)CONCAT44(local_78._4_4_,DVar2);
    ppuStack_70 = &PTR_vftable_14007ad08;
    cchWideChar = 0;
  }
  else {
    local_78 = (undefined8 *)((ulonglong)local_78 & 0xffffffff00000000);
    ppuStack_70 = &PTR_vftable_14007ac70;
  }
  if ((ppuStack_70[1] == DAT_14007ac78) && ((int)local_78 == 0)) {
    if (cchWideChar == 0) {
      *param_1 = 0;
      param_1[2] = 0;
      param_1[3] = 7;
      *(undefined2 *)param_1 = 0;
    }
    else {
      local_30 = 0;
      uStack_28 = 7;
      local_40 = (LPWSTR **)0x0;
      FUN_1400101a0((longlong *)&local_40,(ulonglong)cchWideChar,0);
      ppppWVar4 = &local_40;
      if (7 < uStack_28) {
        ppppWVar4 = (LPWSTR ***)local_40;
      }
      iVar3 = MultiByteToWideChar(0xfde9,0,param_4,-1,(LPWSTR)ppppWVar4,cchWideChar);
      if (iVar3 < 0) {
        FUN_1400036f0(local_68,(undefined8 *)"MultiByteToWideChar failed");
                    /* WARNING: Subroutine does not return */
        _CxxThrowException(local_68,(ThrowInfo *)&DAT_140077a60);
      }
      if (iVar3 == 0) {
        DVar2 = GetLastError();
        if (DVar2 != 0) {
          FUN_1400036f0(local_68,(undefined8 *)"MultiByteToWideChar failed");
                    /* WARNING: Subroutine does not return */
          _CxxThrowException(local_68,(ThrowInfo *)&DAT_140077a60);
        }
        iVar3 = 0;
      }
      else {
        iVar3 = iVar3 + -1;
      }
      uVar1 = local_30;
      if (iVar3 < (int)cchWideChar) {
        uVar5 = (ulonglong)iVar3;
        if (local_30 < uVar5) {
          uVar7 = uVar5 - local_30;
          if (uStack_28 - local_30 < uVar7) {
            FUN_140013620(&local_40,uVar7,local_30,uVar7,0);
          }
          else {
            ppppWVar4 = &local_40;
            if (7 < uStack_28) {
              ppppWVar4 = (LPWSTR ***)local_40;
            }
            pWVar8 = (LPWSTR)((longlong)ppppWVar4 + local_30 * 2);
            uVar6 = uVar7;
            local_30 = uVar5;
            if (uVar7 != 0) {
              for (; uVar6 != 0; uVar6 = uVar6 - 1) {
                *pWVar8 = L'\0';
                pWVar8 = pWVar8 + 1;
              }
            }
            *(WCHAR *)((longlong)ppppWVar4 + (uVar1 + uVar7) * 2) = L'\0';
          }
        }
        else {
          ppppWVar4 = &local_40;
          if (7 < uStack_28) {
            ppppWVar4 = (LPWSTR ***)local_40;
          }
          local_30 = uVar5;
          *(WCHAR *)((longlong)ppppWVar4 + uVar5 * 2) = L'\0';
        }
        FUN_14000e4b0((longlong *)&local_40);
      }
      *param_1 = local_40;
      param_1[1] = uStack_38;
      param_1[2] = local_30;
      param_1[3] = uStack_28;
    }
    FUN_14002f160(local_20 ^ (ulonglong)auStackY_a8);
    return;
  }
  FUN_140003760(local_68,&local_78,(undefined8 *)"MultiByteToWideChar for size failed");
                    /* WARNING: Subroutine does not return */
  _CxxThrowException(local_68,(ThrowInfo *)&DAT_140077a60);
}


// FUNCTION_END

// FUNCTION_START: FUN_140018340 @ 140018340