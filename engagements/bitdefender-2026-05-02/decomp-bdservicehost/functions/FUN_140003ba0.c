void FUN_140003ba0(undefined8 *param_1,PCCERT_CONTEXT param_2,undefined8 param_3,uint param_4,
                  undefined8 param_5,int *param_6)

{
  code *pcVar1;
  DWORD DVar2;
  DWORD DVar3;
  LPWSTR ***ppppWVar4;
  undefined **ppuVar5;
  ulonglong uVar6;
  ulonglong uVar7;
  ulonglong uVar8;
  ulonglong uVar9;
  LPWSTR pWVar10;
  undefined1 auStackY_b8 [32];
  undefined4 uStack_84;
  LPWSTR **local_60;
  undefined8 uStack_58;
  ulonglong local_50;
  ulonglong uStack_48;
  ulonglong local_40;
  
  local_40 = DAT_14007a060 ^ (ulonglong)auStackY_b8;
  uVar6 = (ulonglong)param_4;
  DVar2 = CertGetNameStringW(param_2,4,param_4,(void *)0x0,(LPWSTR)0x0,0);
  uVar7 = (ulonglong)DVar2;
  if (DVar2 == 0) {
    DVar3 = GetLastError();
    *(ulonglong *)param_6 = CONCAT44(uStack_84,DVar3);
    *(undefined ***)(param_6 + 2) = &PTR_vftable_14007ad08;
    ppuVar5 = *(undefined ***)(param_6 + 2);
  }
  else {
    *param_6 = 0;
    *(undefined ***)(param_6 + 2) = &PTR_vftable_14007ac70;
    ppuVar5 = &PTR_vftable_14007ac70;
  }
  if ((ppuVar5[1] == DAT_14007ac78) && (*param_6 == 0)) {
    local_50 = 0;
    uStack_48 = 7;
    local_60 = (LPWSTR **)0x0;
    if (DVar2 == 0) {
      local_50 = uVar7;
      *(undefined2 *)((longlong)&local_60 + uVar7 * 2) = 0;
    }
    else if (uVar7 < 8) {
      ppppWVar4 = &local_60;
      local_50 = uVar7;
      for (uVar6 = uVar7; uVar6 != 0; uVar6 = uVar6 - 1) {
        *(undefined2 *)ppppWVar4 = 0;
        ppppWVar4 = (LPWSTR ***)((longlong)ppppWVar4 + 2);
      }
      *(undefined2 *)((longlong)&local_60 + uVar7 * 2) = 0;
    }
    else {
      FUN_140013620(&local_60,uVar7,uVar6,uVar7,0);
    }
    ppppWVar4 = &local_60;
    if (7 < uStack_48) {
      ppppWVar4 = (LPWSTR ***)local_60;
    }
    DVar2 = CertGetNameStringW(param_2,4,param_4,(void *)0x0,(LPWSTR)ppppWVar4,DVar2);
    if (DVar2 == 0) {
      DVar2 = GetLastError();
      *(ulonglong *)param_6 = CONCAT44(uStack_84,DVar2);
      *(undefined ***)(param_6 + 2) = &PTR_vftable_14007ad08;
      DVar2 = 0;
    }
    else if (DVar2 == 1) {
      *(ulonglong *)param_6 = CONCAT44(uStack_84,0x490);
      *(undefined ***)(param_6 + 2) = &PTR_vftable_14007ad08;
    }
    else {
      *param_6 = 0;
      *(undefined ***)(param_6 + 2) = &PTR_vftable_14007ac70;
    }
    uVar6 = local_50;
    if ((*(undefined **)(*(longlong *)(param_6 + 2) + 8) == DAT_14007ac78) && (*param_6 == 0)) {
      uVar7 = (ulonglong)(DVar2 - 1);
      if (local_50 < uVar7) {
        uVar9 = uVar7 - local_50;
        if (uStack_48 - local_50 < uVar9) {
          FUN_140013620(&local_60,uVar9,local_50,uVar9,0);
        }
        else {
          ppppWVar4 = &local_60;
          if (7 < uStack_48) {
            ppppWVar4 = (LPWSTR ***)local_60;
          }
          pWVar10 = (LPWSTR)((longlong)ppppWVar4 + local_50 * 2);
          uVar8 = uVar9;
          local_50 = uVar7;
          if (uVar9 != 0) {
            for (; uVar8 != 0; uVar8 = uVar8 - 1) {
              *pWVar10 = L'\0';
              pWVar10 = pWVar10 + 1;
            }
          }
          *(WCHAR *)((longlong)ppppWVar4 + (uVar6 + uVar9) * 2) = L'\0';
        }
      }
      else {
        ppppWVar4 = &local_60;
        if (7 < uStack_48) {
          ppppWVar4 = (LPWSTR ***)local_60;
        }
        local_50 = uVar7;
        *(WCHAR *)((longlong)ppppWVar4 + uVar7 * 2) = L'\0';
      }
      FUN_14000e4b0((longlong *)&local_60);
      *param_1 = local_60;
      param_1[1] = uStack_58;
      param_1[2] = local_50;
      param_1[3] = uStack_48;
    }
    else {
      *param_1 = 0;
      param_1[2] = 0;
      param_1[3] = 7;
      *(undefined2 *)param_1 = 0;
      if (7 < uStack_48) {
        if ((0xfff < uStack_48 * 2 + 2) &&
           (0x1f < (ulonglong)((longlong)local_60 + (-8 - (longlong)local_60[-1])))) {
          FUN_140035d28();
          pcVar1 = (code *)swi(3);
          (*pcVar1)();
          return;
        }
        FUN_14002f180();
      }
      local_50 = 0;
      uStack_48 = 7;
      local_60 = (LPWSTR **)((ulonglong)local_60 & 0xffffffffffff0000);
    }
  }
  else {
    *param_1 = 0;
    param_1[2] = 0;
    param_1[3] = 7;
    *(undefined2 *)param_1 = 0;
  }
  FUN_14002f160(local_40 ^ (ulonglong)auStackY_b8);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_140003ef0 @ 140003ef0