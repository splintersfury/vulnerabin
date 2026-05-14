void __fastcall FUN_10026b80(HKEY param_1,LPCWSTR param_2,LPCWSTR param_3,void *param_4)

{
  int iVar1;
  code *pcVar2;
  uint uVar3;
  LPCWSTR pWVar4;
  LSTATUS LVar5;
  int *piVar6;
  void *pvVar7;
  uint *puVar8;
  int local_184 [24];
  undefined **local_124 [18];
  int local_dc [24];
  undefined **local_7c [19];
  void *local_30;
  LPCWSTR local_2c;
  HKEY local_28;
  DWORD local_24;
  undefined8 local_20;
  int local_18;
  uint local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_100502a3;
  local_10 = ExceptionList;
  local_14 = DAT_10069054 ^ (uint)&stack0xfffffffc;
  ExceptionList = &local_10;
  local_2c = param_3;
  local_30 = param_4;
  local_28 = (HKEY)0x0;
  LVar5 = RegOpenKeyExW(param_1,param_2,0,0x201,&local_28);
  if (LVar5 == 0) {
    local_20 = 0;
    local_18 = 0;
    pvVar7 = FUN_10001e50(0x7fff);
    iVar1 = (int)pvVar7 + 0xfffe;
    local_20 = CONCAT44(local_20._4_4_,pvVar7);
    local_18 = iVar1;
    _memset(pvVar7,0,0xfffe);
    pWVar4 = local_2c;
    local_20 = CONCAT44(iVar1,(uint *)local_20);
    local_8 = 2;
    local_24 = (iVar1 - (int)(uint *)local_20 >> 1) * 2;
    LVar5 = RegQueryValueExW(local_28,local_2c,(LPDWORD)0x0,(LPDWORD)0x0,(LPBYTE)(uint *)local_20,
                             &local_24);
    if (LVar5 == 0) {
      puVar8 = (uint *)local_20;
      do {
        uVar3 = *puVar8;
        puVar8 = (uint *)((int)puVar8 + 2);
      } while ((short)uVar3 != 0);
      FUN_10001d40(local_30,(uint *)local_20,(int)puVar8 - ((int)(uint *)local_20 + 2) >> 1);
    }
    else {
      piVar6 = FUN_100034b0(local_184,4,0x10060d74);
      local_8._0_1_ = 3;
      if (((((char)piVar6[0x12] != '\0') &&
           (FUN_10007f80(piVar6,"RegQueryValueEx "), (char)piVar6[0x12] != '\0')) &&
          (FUN_100082c0(piVar6,pWVar4), (char)piVar6[0x12] != '\0')) &&
         (FUN_10007f80(piVar6," failed "), (char)piVar6[0x12] != '\0')) {
        FUN_10027670(piVar6,LVar5);
      }
      FUN_10003240((int)local_124);
      local_8 = CONCAT31(local_8._1_3_,4);
      local_124[0] = std::ios_base::vftable;
      std::ios_base::_Ios_base_dtor((ios_base *)local_124);
    }
    RegCloseKey(local_28);
    if ((uint *)local_20 != (uint *)0x0) {
      pvVar7 = (uint *)local_20;
      if ((0xfff < (local_18 - (int)(uint *)local_20 & 0xfffffffeU)) &&
         (pvVar7 = *(void **)((int)(uint *)local_20 + -4),
         0x1f < (uint)((int)(uint *)local_20 + (-4 - (int)pvVar7)))) {
        FUN_10032f7f();
        pcVar2 = (code *)swi(3);
        (*pcVar2)();
        return;
      }
      FUN_1002e346(pvVar7);
    }
  }
  else {
    piVar6 = FUN_100034b0(local_dc,4,0x10060d74);
    local_8 = 0;
    if ((((char)piVar6[0x12] != '\0') &&
        (FUN_10007f80(piVar6,"RegOpenKeyEx "), (char)piVar6[0x12] != '\0')) &&
       ((FUN_100082c0(piVar6,param_2), (char)piVar6[0x12] != '\0' &&
        (FUN_10007f80(piVar6," failed "), (char)piVar6[0x12] != '\0')))) {
      FUN_10027670(piVar6,LVar5);
    }
    FUN_10003240((int)local_7c);
    local_8 = 1;
    local_7c[0] = std::ios_base::vftable;
    std::ios_base::_Ios_base_dtor((ios_base *)local_7c);
  }
  ExceptionList = local_10;
  FUN_1002e315(local_14 ^ (uint)&stack0xfffffffc);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_10026e10 @ 10026e10