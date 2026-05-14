void FUN_1400067c0(undefined8 *param_1,undefined8 *param_2,undefined8 param_3)

{
  code *pcVar1;
  ulonglong uVar2;
  DWORD DVar3;
  undefined1 (*pauVar4) [16];
  undefined1 (*pauVar5) [16];
  ulonglong uVar6;
  ulonglong uVar7;
  ulonglong uVar8;
  undefined2 *puVar9;
  undefined1 auStackY_98 [32];
  undefined4 uStack_64;
  undefined1 (*local_48 [2]) [16];
  ulonglong local_38;
  ulonglong uStack_30;
  ulonglong local_28;
  
  local_28 = DAT_14007a060 ^ (ulonglong)auStackY_98;
  local_38 = 0;
  uStack_30 = 7;
  local_48[0] = (undefined1 (*) [16])0x0;
  FUN_140013620(local_48,0x7fff,param_3,0x7fff,0);
  pauVar4 = (undefined1 (*) [16])local_48;
  if (7 < uStack_30) {
    pauVar4 = local_48[0];
  }
  DVar3 = GetModuleFileNameW((HMODULE)0x0,(LPWSTR)pauVar4,0x7fff);
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
         (0x1f < (ulonglong)((longlong)local_48[0] + (-8 - *(longlong *)(local_48[0][-1] + 8))))) {
LAB_140006b53:
        FUN_140035d28();
        pcVar1 = (code *)swi(3);
        (*pcVar1)();
        return;
      }
      FUN_14002f180();
    }
    local_38 = 0;
    uStack_30 = 7;
    local_48[0] = (undefined1 (*) [16])((ulonglong)local_48[0] & 0xffffffffffff0000);
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
         (0x1f < (ulonglong)((longlong)local_48[0] + (-8 - *(longlong *)(local_48[0][-1] + 8)))))
      goto LAB_140006b53;
      FUN_14002f180();
    }
    local_38 = 0;
    uStack_30 = 7;
    local_48[0] = (undefined1 (*) [16])((ulonglong)local_48[0] & 0xffffffffffff0000);
  }
  else {
    pauVar4 = (undefined1 (*) [16])local_48;
    if (7 < uStack_30) {
      pauVar4 = local_48[0];
    }
    pauVar4 = FUN_14003126c(pauVar4,0x5c);
    uVar2 = local_38;
    if (pauVar4 == (undefined1 (*) [16])0x0) {
      *param_2 = CONCAT44(uStack_64,0x1f);
      param_2[1] = &PTR_vftable_14007ad08;
      *param_1 = 0;
      param_1[2] = 0;
      param_1[3] = 7;
      *(undefined2 *)param_1 = 0;
      if (7 < uStack_30) {
        if ((0xfff < uStack_30 * 2 + 2) &&
           (0x1f < (ulonglong)((longlong)local_48[0] + (-8 - *(longlong *)(local_48[0][-1] + 8)))))
        goto LAB_140006b53;
        FUN_14002f180();
      }
      local_38 = 0;
      uStack_30 = 7;
      local_48[0] = (undefined1 (*) [16])((ulonglong)local_48[0] & 0xffffffffffff0000);
    }
    else {
      pauVar5 = (undefined1 (*) [16])local_48;
      if (7 < uStack_30) {
        pauVar5 = local_48[0];
      }
      uVar6 = (ulonglong)((int)((longlong)pauVar4 - (longlong)pauVar5 >> 1) + 1);
      if (local_38 < uVar6) {
        uVar8 = uVar6 - local_38;
        if (uStack_30 - local_38 < uVar8) {
          FUN_140013620(local_48,uVar8,local_38,uVar8,0);
        }
        else {
          pauVar4 = (undefined1 (*) [16])local_48;
          if (7 < uStack_30) {
            pauVar4 = local_48[0];
          }
          puVar9 = (undefined2 *)(*pauVar4 + local_38 * 2);
          uVar7 = uVar8;
          local_38 = uVar6;
          if (uVar8 != 0) {
            for (; uVar7 != 0; uVar7 = uVar7 - 1) {
              *puVar9 = 0;
              puVar9 = puVar9 + 1;
            }
          }
          *(undefined2 *)((longlong)pauVar4 + (uVar8 + uVar2) * 2) = 0;
        }
      }
      else {
        pauVar4 = (undefined1 (*) [16])local_48;
        if (7 < uStack_30) {
          pauVar4 = local_48[0];
        }
        local_38 = uVar6;
        *(undefined2 *)(*pauVar4 + uVar6 * 2) = 0;
      }
      FUN_14000e4b0((longlong *)local_48);
      *(undefined4 *)param_2 = 0;
      param_2[1] = &PTR_vftable_14007ac70;
      *param_1 = local_48[0];
      param_1[1] = local_48[1];
      param_1[2] = local_38;
      param_1[3] = uStack_30;
    }
  }
  FUN_14002f160(local_28 ^ (ulonglong)auStackY_98);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_140006b60 @ 140006b60