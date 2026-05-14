void __cdecl FUN_10027320(undefined4 param_1,LPBYTE param_2)

{
  LSTATUS LVar1;
  int *piVar2;
  int local_174 [24];
  undefined **local_114 [18];
  int local_cc [24];
  undefined **local_6c [19];
  HKEY local_20;
  DWORD local_1c [2];
  uint local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_1005033b;
  local_10 = ExceptionList;
  local_14 = DAT_10069054 ^ (uint)&stack0xfffffffc;
  ExceptionList = &local_10;
  local_20 = (HKEY)0x0;
  LVar1 = RegOpenKeyExW((HKEY)0x80000003,L".DEFAULT\\Software\\SetID",0,0x201,&local_20);
  if (LVar1 == 0) {
    local_1c[1] = 4;
    LVar1 = RegQueryValueExW(local_20,L"rtl",(LPDWORD)0x0,local_1c,param_2,local_1c + 1);
    if (LVar1 == 0) {
      if (local_1c[0] != 4) goto LAB_100274e5;
    }
    else {
      piVar2 = FUN_100034b0(local_174,4,0x10060d74);
      local_8 = 2;
      if (((((char)piVar2[0x12] != '\0') &&
           (FUN_10007f80(piVar2,"RegQueryValueEx "), (char)piVar2[0x12] != '\0')) &&
          (FUN_100082c0(piVar2,(short *)&DAT_1005fe18), (char)piVar2[0x12] != '\0')) &&
         (FUN_10007f80(piVar2," failed "), (char)piVar2[0x12] != '\0')) {
        FUN_10027670(piVar2,LVar1);
      }
      FUN_10003240((int)local_114);
      local_8 = 3;
      local_114[0] = std::ios_base::vftable;
      std::ios_base::_Ios_base_dtor((ios_base *)local_114);
    }
    RegCloseKey(local_20);
  }
  else {
    piVar2 = FUN_100034b0(local_cc,4,0x10060d74);
    local_8 = 0;
    if ((((char)piVar2[0x12] != '\0') &&
        (FUN_10007f80(piVar2,"RegOpenKeyEx "), (char)piVar2[0x12] != '\0')) &&
       ((FUN_100082c0(piVar2,L".DEFAULT\\Software\\SetID"), (char)piVar2[0x12] != '\0' &&
        (FUN_10007f80(piVar2," failed "), (char)piVar2[0x12] != '\0')))) {
      FUN_10027670(piVar2,LVar1);
    }
    FUN_10003240((int)local_6c);
    local_8 = 1;
    local_6c[0] = std::ios_base::vftable;
    std::ios_base::_Ios_base_dtor((ios_base *)local_6c);
  }
LAB_100274e5:
  ExceptionList = local_10;
  FUN_1002e315(local_14 ^ (uint)&stack0xfffffffc);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_10027500 @ 10027500