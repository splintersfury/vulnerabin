void __fastcall FUN_100270b0(HKEY param_1,LPCWSTR param_2,LPCWSTR param_3,int *param_4)

{
  LPCWSTR pWVar1;
  LSTATUS LVar2;
  int *piVar3;
  int iVar4;
  uint uVar5;
  void *pvVar6;
  void *pvVar7;
  size_t _Size;
  int local_174 [24];
  undefined **local_114 [18];
  int local_cc [24];
  undefined **local_6c [19];
  LPCWSTR local_20;
  HKEY local_1c;
  uint local_18;
  uint local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_1005033b;
  local_10 = ExceptionList;
  local_14 = DAT_10069054 ^ (uint)&stack0xfffffffc;
  ExceptionList = &local_10;
  local_20 = param_3;
  local_1c = (HKEY)0x0;
  LVar2 = RegOpenKeyExW(param_1,param_2,0,0x201,&local_1c);
  if (LVar2 != 0) {
    piVar3 = FUN_100034b0(local_cc,4,0x10060d74);
    local_8 = 0;
    if (((((char)piVar3[0x12] != '\0') &&
         (FUN_10007f80(piVar3,"RegOpenKeyEx "), (char)piVar3[0x12] != '\0')) &&
        (FUN_100082c0(piVar3,param_2), (char)piVar3[0x12] != '\0')) &&
       (FUN_10007f80(piVar3," failed "), (char)piVar3[0x12] != '\0')) {
      FUN_10027670(piVar3,LVar2);
    }
    FUN_10003240((int)local_6c);
    local_8 = 1;
    local_6c[0] = std::ios_base::vftable;
    std::ios_base::_Ios_base_dtor((ios_base *)local_6c);
    goto LAB_1002723a;
  }
  pvVar7 = (void *)param_4[1];
  iVar4 = *param_4;
  uVar5 = (int)pvVar7 - iVar4;
  if (uVar5 < 0x8000) {
    if (uVar5 < 0x7fff) {
      if (0x7ffe < (uint)(param_4[2] - iVar4)) {
        pvVar6 = (void *)((int)pvVar7 + (0x7fff - uVar5));
        _memset(pvVar7,0,0x7fff - uVar5);
        goto LAB_100271ec;
      }
      FUN_10027560(param_4,0x7fff);
      pvVar7 = (void *)param_4[1];
    }
  }
  else {
    pvVar6 = (void *)(iVar4 + 0x7fff);
LAB_100271ec:
    param_4[1] = (int)pvVar6;
    pvVar7 = pvVar6;
  }
  pWVar1 = local_20;
  local_18 = (int)pvVar7 - *param_4;
  local_20 = (LPCWSTR)RegQueryValueExW(local_1c,local_20,(LPDWORD)0x0,(LPDWORD)0x0,(LPBYTE)*param_4,
                                       &local_18);
  if (local_20 == (LPCWSTR)0x0) {
    pvVar7 = (void *)param_4[1];
    iVar4 = *param_4;
    uVar5 = (int)pvVar7 - iVar4;
    if (local_18 < uVar5) {
      iVar4 = iVar4 + local_18;
LAB_10027226:
      param_4[1] = iVar4;
    }
    else if (uVar5 < local_18) {
      if (local_18 <= (uint)(param_4[2] - iVar4)) {
        _Size = local_18 - uVar5;
        _memset(pvVar7,0,_Size);
        iVar4 = _Size + (int)pvVar7;
        goto LAB_10027226;
      }
      FUN_10027560(param_4,local_18);
    }
  }
  else {
    piVar3 = FUN_100034b0(local_174,4,0x10060d74);
    local_8 = 2;
    if ((((char)piVar3[0x12] != '\0') &&
        (FUN_10007f80(piVar3,"RegQueryValueEx "), (char)piVar3[0x12] != '\0')) &&
       ((FUN_100082c0(piVar3,pWVar1), (char)piVar3[0x12] != '\0' &&
        (FUN_10007f80(piVar3," failed "), (char)piVar3[0x12] != '\0')))) {
      FUN_10027670(piVar3,local_20);
    }
    FUN_10003240((int)local_114);
    local_8 = 3;
    local_114[0] = std::ios_base::vftable;
    std::ios_base::_Ios_base_dtor((ios_base *)local_114);
  }
  RegCloseKey(local_1c);
LAB_1002723a:
  ExceptionList = local_10;
  FUN_1002e315(local_14 ^ (uint)&stack0xfffffffc);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_10027320 @ 10027320