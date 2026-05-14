void __fastcall FUN_10026e10(undefined4 param_1,LPCWSTR param_2,LPCWSTR param_3,short *param_4)

{
  short sVar1;
  LPCWSTR pWVar2;
  LSTATUS LVar3;
  int *piVar4;
  short *psVar5;
  int local_174 [24];
  undefined **local_114 [18];
  int local_cc [24];
  undefined **local_6c [19];
  LPCWSTR local_20;
  short *local_1c;
  HKEY local_18;
  uint local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_100502f6;
  local_10 = ExceptionList;
  local_14 = DAT_10069054 ^ (uint)&stack0xfffffffc;
  ExceptionList = &local_10;
  local_20 = param_3;
  local_1c = param_4;
  local_18 = (HKEY)0x0;
  LVar3 = RegOpenKeyExW((HKEY)0x80000002,param_2,0,0x202,&local_18);
  if (LVar3 != 0) {
    piVar4 = FUN_100034b0(local_cc,4,0x10060da8);
    local_8 = 0;
    if (((((char)piVar4[0x12] != '\0') &&
         (FUN_10007f80(piVar4,"RegOpenKeyEx "), (char)piVar4[0x12] != '\0')) &&
        (FUN_100082c0(piVar4,param_2), (char)piVar4[0x12] != '\0')) &&
       (FUN_10007f80(piVar4," failed "), (char)piVar4[0x12] != '\0')) {
      FUN_10027670(piVar4,LVar3);
    }
    FUN_10003240((int)local_6c);
    local_8 = 1;
    local_6c[0] = std::ios_base::vftable;
    std::ios_base::_Ios_base_dtor((ios_base *)local_6c);
    local_8 = 0xffffffff;
    LVar3 = RegCreateKeyExW((HKEY)0x80000002,param_2,0,(LPWSTR)0x0,0,0xf023f,
                            (LPSECURITY_ATTRIBUTES)0x0,&local_18,(LPDWORD)0x0);
    param_4 = local_1c;
    if (LVar3 != 0) {
      piVar4 = FUN_100034b0(local_cc,4,0x10060da8);
      local_8 = 2;
      if ((((char)piVar4[0x12] != '\0') &&
          (FUN_10007f80(piVar4,"RegCreateKeyEx "), (char)piVar4[0x12] != '\0')) &&
         ((FUN_100082c0(piVar4,param_2), (char)piVar4[0x12] != '\0' &&
          (FUN_10007f80(piVar4," failed "), (char)piVar4[0x12] != '\0')))) {
        FUN_10027670(piVar4,LVar3);
      }
      FUN_10003240((int)local_6c);
      local_8 = 3;
      local_6c[0] = std::ios_base::vftable;
      std::ios_base::_Ios_base_dtor((ios_base *)local_6c);
      goto LAB_10027092;
    }
  }
  pWVar2 = local_20;
  psVar5 = param_4;
  do {
    sVar1 = *psVar5;
    psVar5 = psVar5 + 1;
  } while (sVar1 != 0);
  LVar3 = RegSetValueExW(local_18,local_20,0,1,(BYTE *)param_4,
                         ((int)psVar5 - (int)(param_4 + 1) >> 1) * 2 + 2);
  if (LVar3 != 0) {
    piVar4 = FUN_100034b0(local_174,4,0x10060da8);
    local_8 = 4;
    if ((((char)piVar4[0x12] != '\0') &&
        (FUN_10007f80(piVar4,"RegSetValueEx "), (char)piVar4[0x12] != '\0')) &&
       ((FUN_100082c0(piVar4,pWVar2), (char)piVar4[0x12] != '\0' &&
        (FUN_10007f80(piVar4," failed "), (char)piVar4[0x12] != '\0')))) {
      FUN_10027670(piVar4,LVar3);
    }
    FUN_10003240((int)local_114);
    local_8 = 5;
    local_114[0] = std::ios_base::vftable;
    std::ios_base::_Ios_base_dtor((ios_base *)local_114);
  }
  RegCloseKey(local_18);
LAB_10027092:
  ExceptionList = local_10;
  FUN_1002e315(local_14 ^ (uint)&stack0xfffffffc);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_100270b0 @ 100270b0