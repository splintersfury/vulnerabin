void __fastcall FUN_100282a0(undefined8 *param_1,undefined4 *param_2)

{
  BYTE *pBVar1;
  bool bVar2;
  HCRYPTHASH hHash;
  BOOL BVar3;
  DWORD DVar4;
  undefined4 extraout_ECX;
  BYTE *pbData;
  uint uVar5;
  undefined **ppuVar6;
  BYTE *pBVar7;
  int local_50 [5];
  undefined **local_3c;
  BYTE *local_38;
  uint local_34;
  undefined8 local_30;
  undefined8 local_28;
  HCRYPTPROV local_20;
  HCRYPTPROV local_1c;
  HCRYPTHASH local_18;
  uint local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_1005060d;
  local_10 = ExceptionList;
  local_14 = DAT_10069054 ^ (uint)&stack0xfffffffc;
  ExceptionList = &local_10;
  local_28 = CONCAT44(param_1,(DWORD)local_28);
  FUN_10027d40(&local_20);
  local_38 = (BYTE *)0x0;
  local_1c = local_20;
  local_8._0_1_ = 2;
  local_8._1_3_ = 0;
  FUN_10027e40(&local_18,&local_1c,extraout_ECX,(HCRYPTKEY *)&local_38);
  local_8._0_1_ = 5;
  pBVar1 = (BYTE *)param_2[1];
  hHash = local_18;
  for (pBVar7 = (BYTE *)*param_2; local_18 = hHash, pBVar7 != pBVar1; pBVar7 = pBVar7 + 0x18) {
    pbData = pBVar7;
    if (7 < *(uint *)(pBVar7 + 0x14)) {
      pbData = *(BYTE **)pBVar7;
    }
    local_30 = 0;
    BVar3 = CryptHashData(hHash,pbData,*(int *)(pBVar7 + 0x10) * 2,0);
    if (BVar3 == 0) {
      DVar4 = GetLastError();
      ppuVar6 = &PTR_vftable_10069ab8;
    }
    else {
      ppuVar6 = &PTR_vftable_10069aa8;
      DVar4 = (DWORD)local_30;
    }
    if ((ppuVar6[1] == DAT_10069aac) && (DVar4 == 0)) {
      bVar2 = false;
    }
    else {
      bVar2 = true;
    }
    if (bVar2) {
      FUN_10027cd0(local_50,(uint *)"CryptHashData failed",DVar4,(int *)ppuVar6);
                    /* WARNING: Subroutine does not return */
      __CxxThrowException_8(local_50,&DAT_10067674);
    }
    hHash = local_18;
  }
  local_30 = CONCAT44(hHash,(DWORD)local_30);
  local_8 = CONCAT31(local_8._1_3_,6);
  local_1c = 0;
  *param_1 = 0;
  local_28._0_4_ = 0;
  local_28._4_4_ = 0;
  *(undefined4 *)(param_1 + 1) = 0;
  BVar3 = CryptGetHashParam(hHash,2,(BYTE *)0x0,&local_1c,0);
  if (BVar3 == 0) {
    DVar4 = GetLastError();
    ppuVar6 = &PTR_vftable_10069ab8;
    local_34 = 0;
  }
  else {
    ppuVar6 = &PTR_vftable_10069aa8;
    local_34 = local_1c;
    DVar4 = (DWORD)local_28;
  }
  local_3c = ppuVar6;
  if (((ppuVar6[1] == DAT_10069aac) && (DVar4 == 0)) && (local_34 != 0)) {
    local_38 = (BYTE *)FUN_1002e6a3(local_34);
    if (local_38 != (BYTE *)0x0) {
      local_28._4_4_ = local_34;
      BVar3 = CryptGetHashParam(hHash,2,local_38,&local_34,0);
      if (BVar3 == 0) {
        DVar4 = GetLastError();
        *(undefined4 *)param_1 = 0;
        *(undefined4 *)((int)param_1 + 4) = 0;
        thunk_FUN_100330ca(local_38);
        ppuVar6 = &PTR_vftable_10069ab8;
      }
      else {
        uVar5 = local_28._4_4_;
        if (local_34 < local_28._4_4_) {
          uVar5 = local_34;
        }
        *(BYTE **)param_1 = local_38;
        *(uint *)((int)param_1 + 4) = uVar5;
        ppuVar6 = local_3c;
      }
      goto LAB_1002847f;
    }
    DVar4 = 8;
    ppuVar6 = &PTR_vftable_10069ab8;
  }
  *(undefined4 *)((int)param_1 + 4) = 0;
  *(undefined4 *)param_1 = 0;
LAB_1002847f:
  if ((ppuVar6[1] == DAT_10069aac) && (DVar4 == 0)) {
    if (local_18 != 0) {
      CryptDestroyHash(local_18);
      local_18 = 0;
    }
    if (local_20 != 0) {
      CryptReleaseContext(local_20,0);
    }
    ExceptionList = local_10;
    FUN_1002e315(local_14 ^ (uint)&stack0xfffffffc);
    return;
  }
  FUN_10027cd0(local_50,(uint *)"CryptGetHashParam failed",DVar4,(int *)ppuVar6);
                    /* WARNING: Subroutine does not return */
  __CxxThrowException_8(local_50,&DAT_10067674);
}


// FUNCTION_END

// FUNCTION_START: FUN_10028510 @ 10028510