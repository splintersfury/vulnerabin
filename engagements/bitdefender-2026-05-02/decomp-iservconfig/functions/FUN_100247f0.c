undefined4 __fastcall FUN_100247f0(short *param_1)

{
  uint *puVar1;
  code *pcVar2;
  int iVar3;
  int *piVar4;
  ios_base *piVar5;
  undefined4 uVar6;
  void *pvVar7;
  undefined4 extraout_ECX;
  uint uVar8;
  LPCWSTR pWVar9;
  int local_17c [24];
  undefined **local_11c [18];
  int local_d4 [24];
  undefined **local_74 [18];
  void *local_2c;
  int local_20 [2];
  uint local_18;
  int local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_10050166;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  iVar3 = FUN_1001e130();
  local_14 = 6;
  puVar1 = (uint *)(iVar3 + 0x60);
  FUN_10023ea0(puVar1,local_20,&local_14);
  if ((*(char *)(local_18 + 0xd) != '\0') || (uVar8 = local_18, 6 < *(int *)(local_18 + 0x10))) {
    uVar8 = *puVar1;
  }
  if (uVar8 == *puVar1) {
    pWVar9 = L"";
LAB_100248bf:
    uVar6 = FUN_10026b80((HKEY)0x80000002,pWVar9,L"AnonId",param_1);
    if ((char)uVar6 != '\0') goto LAB_10024a4a;
  }
  else {
    pWVar9 = (LPCWSTR)(uVar8 + 0x14);
    if (7 < *(uint *)(uVar8 + 0x28)) {
      pWVar9 = *(LPCWSTR *)pWVar9;
    }
    if (pWVar9 != (LPCWSTR)0x0) goto LAB_100248bf;
    piVar4 = FUN_100034b0(local_d4,4,0x10060c34);
    local_8 = 0;
    if ((char)piVar4[0x12] != '\0') {
      FUN_100082c0(piVar4,L"failed get RegPathProduct");
    }
    FUN_10003240((int)local_74);
    local_8 = 1;
    local_74[0] = std::ios_base::vftable;
    std::ios_base::_Ios_base_dtor((ios_base *)local_74);
    local_8 = 0xffffffff;
  }
  piVar4 = FUN_100034b0(local_d4,0x10,0x10060bec);
  local_8 = 2;
  if ((char)piVar4[0x12] != '\0') {
    FUN_100082c0(piVar4,L"LoadAnonId failed, try to generate it");
  }
  FUN_10003240((int)local_74);
  local_8 = 3;
  local_74[0] = std::ios_base::vftable;
  std::ios_base::_Ios_base_dtor((ios_base *)local_74);
  local_8 = 0xffffffff;
  piVar4 = (int *)FUN_1002a9e0();
  FUN_10005380(param_1,piVar4);
  if (7 < local_18) {
    pvVar7 = local_2c;
    if (0xfff < local_18 * 2 + 2) {
      pvVar7 = *(void **)((int)local_2c + -4);
      if (0x1f < (uint)((int)local_2c + (-4 - (int)pvVar7))) {
        FUN_10032f7f();
        pcVar2 = (code *)swi(3);
        uVar6 = (*pcVar2)();
        return uVar6;
      }
    }
    FUN_1002e346(pvVar7);
  }
  if (7 < *(uint *)(param_1 + 10)) {
    param_1 = *(short **)param_1;
  }
  iVar3 = FUN_1001e130();
  local_14 = 6;
  puVar1 = (uint *)(iVar3 + 0x60);
  FUN_10023ea0(puVar1,local_20,&local_14);
  if ((*(char *)(local_18 + 0xd) != '\0') || (6 < *(int *)(local_18 + 0x10))) {
    local_18 = *puVar1;
  }
  if (local_18 == *puVar1) {
    pWVar9 = L"";
  }
  else {
    pWVar9 = (LPCWSTR)(local_18 + 0x14);
    if (7 < *(uint *)(local_18 + 0x28)) {
      pWVar9 = *(LPCWSTR *)pWVar9;
    }
    if (pWVar9 == (LPCWSTR)0x0) {
      piVar4 = FUN_100034b0(local_17c,4,0x10060c5c);
      local_8 = 4;
      if ((char)piVar4[0x12] != '\0') {
        FUN_100082c0(piVar4,L"failed get RegPathProduct");
      }
      FUN_10003240((int)local_11c);
      piVar5 = (ios_base *)local_11c;
      local_8 = 5;
      local_11c[0] = std::ios_base::vftable;
      std::ios_base::_Ios_base_dtor(piVar5);
      ExceptionList = local_10;
      return CONCAT31((int3)((uint)piVar5 >> 8),1);
    }
  }
  uVar6 = FUN_10026e10(extraout_ECX,pWVar9,L"AnonId",param_1);
LAB_10024a4a:
  ExceptionList = local_10;
  return CONCAT31((int3)((uint)uVar6 >> 8),1);
}


// FUNCTION_END

// FUNCTION_START: FUN_10024a70 @ 10024a70

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */