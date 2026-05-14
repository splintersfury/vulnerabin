void __fastcall FUN_1001daa0(undefined4 *param_1,DWORD *param_2)

{
  code *pcVar1;
  DWORD DVar2;
  uint uVar3;
  undefined1 (*pauVar4) [16];
  undefined1 (*pauVar5) [16];
  int iVar6;
  uint uStack_60;
  undefined1 (*local_44 [4]) [16];
  uint local_34;
  uint uStack_30;
  uint local_2c;
  undefined1 *puStack_24;
  undefined1 *local_20;
  void *local_1c;
  undefined1 *puStack_18;
  undefined4 local_14;
  
  puStack_24 = &stack0xfffffffc;
  puStack_18 = &LAB_1004f9bd;
  local_1c = ExceptionList;
  uStack_60 = DAT_10069054 ^ (uint)&stack0xfffffff0;
  local_20 = (undefined1 *)&uStack_60;
  ExceptionList = &local_1c;
  local_34 = 0;
  uStack_30 = 7;
  local_44[0] = (undefined1 (*) [16])0x0;
  local_14 = 1;
  local_2c = uStack_60;
  FUN_1000f950(local_44,0x7fff,0);
  pauVar4 = (undefined1 (*) [16])local_44;
  if (7 < uStack_30) {
    pauVar4 = local_44[0];
  }
  DVar2 = GetModuleFileNameW((HMODULE)0x0,(LPWSTR)pauVar4,0x7fff);
  if (DVar2 == 0) {
    DVar2 = GetLastError();
    *param_2 = DVar2;
    param_2[1] = (DWORD)&PTR_vftable_10069ab8;
    *param_1 = 0;
    param_1[4] = 0;
    param_1[5] = 7;
    *(undefined2 *)param_1 = 0;
    if (uStack_30 < 8) goto LAB_1001db9e;
    pauVar4 = local_44[0];
    if (0xfff < uStack_30 * 2 + 2) {
      pauVar4 = *(undefined1 (**) [16])((int)local_44[0][-1] + 0xc);
      uVar3 = (int)local_44[0] + (-4 - (int)pauVar4);
joined_r0x1001dc83:
      if (0x1f < uVar3) {
LAB_1001dd65:
        FUN_10032f7f();
        pcVar1 = (code *)swi(3);
        (*pcVar1)();
        return;
      }
    }
  }
  else {
    if ((DVar2 == 0x7fff) && (DVar2 = GetLastError(), DVar2 != 0)) {
      *param_2 = DVar2;
      param_2[1] = (DWORD)&PTR_vftable_10069ab8;
      *param_1 = 0;
      param_1[4] = 0;
      param_1[5] = 7;
      *(undefined2 *)param_1 = 0;
      if (uStack_30 < 8) goto LAB_1001db9e;
      pauVar4 = local_44[0];
      if ((uStack_30 * 2 + 2 < 0x1000) ||
         (pauVar4 = *(undefined1 (**) [16])((int)local_44[0][-1] + 0xc),
         (uint)((int)local_44[0] + (-4 - (int)pauVar4)) < 0x20)) {
        FUN_1002e346(pauVar4);
        FUN_1001dd47();
        return;
      }
      goto LAB_1001dd65;
    }
    pauVar4 = (undefined1 (*) [16])local_44;
    if (7 < uStack_30) {
      pauVar4 = local_44[0];
    }
    pauVar4 = FUN_1002fe24(pauVar4,0x5c);
    if (pauVar4 != (undefined1 (*) [16])0x0) {
      pauVar5 = (undefined1 (*) [16])local_44;
      if (7 < uStack_30) {
        pauVar5 = local_44[0];
      }
      iVar6 = (int)pauVar4 - (int)pauVar5 >> 1;
      uVar3 = iVar6 + 1;
      if (local_34 < uVar3) {
        FUN_1000f950(local_44,uVar3 - local_34,0);
      }
      else {
        pauVar4 = (undefined1 (*) [16])local_44;
        if (7 < uStack_30) {
          pauVar4 = local_44[0];
        }
        local_34 = uVar3;
        *(WCHAR *)((int)*pauVar4 + (iVar6 + 1) * 2) = L'\0';
      }
      FUN_1000ea80((uint *)local_44);
      *param_2 = 0;
      param_2[1] = (DWORD)&PTR_vftable_10069aa8;
      *param_1 = 0;
      param_1[4] = 0;
      param_1[5] = 0;
      *param_1 = local_44[0];
      param_1[1] = local_44[1];
      param_1[2] = local_44[2];
      param_1[3] = local_44[3];
      *(ulonglong *)(param_1 + 4) = CONCAT44(uStack_30,local_34);
      FUN_1001dd47();
      return;
    }
    *param_2 = 0x1f;
    param_2[1] = (DWORD)&PTR_vftable_10069ab8;
    *param_1 = 0;
    param_1[4] = 0;
    param_1[5] = 7;
    *(undefined2 *)param_1 = 0;
    if (uStack_30 < 8) goto LAB_1001db9e;
    pauVar4 = local_44[0];
    if (0xfff < uStack_30 * 2 + 2) {
      pauVar4 = *(undefined1 (**) [16])((int)local_44[0][-1] + 0xc);
      uVar3 = (int)local_44[0] + (-4 - (int)pauVar4);
      goto joined_r0x1001dc83;
    }
  }
  FUN_1002e346(pauVar4);
LAB_1001db9e:
  FUN_1001dd47();
  return;
}


// FUNCTION_END

// FUNCTION_START: Catch_All@1001dd04 @ 1001dd04