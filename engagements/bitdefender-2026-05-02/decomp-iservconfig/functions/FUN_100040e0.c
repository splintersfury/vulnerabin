void __fastcall FUN_100040e0(void *param_1)

{
  wchar_t wVar1;
  code *pcVar2;
  char cVar3;
  uint uVar4;
  DWORD DVar5;
  int *piVar6;
  uint *puVar7;
  uint *puVar8;
  wchar_t *pwVar9;
  LPCWSTR ***ppppWVar10;
  wchar_t *pwVar11;
  int local_104 [24];
  undefined **local_a4 [18];
  undefined **local_5c;
  undefined4 local_58;
  undefined4 local_54;
  int *local_50;
  undefined4 local_4c;
  undefined4 local_48;
  undefined4 local_44;
  undefined4 local_34;
  undefined4 local_30;
  LPCWSTR **local_2c [4];
  int local_1c;
  uint local_18;
  uint local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_1004dc91;
  local_10 = ExceptionList;
  uVar4 = DAT_10069054 ^ (uint)&stack0xfffffffc;
  ExceptionList = &local_10;
  local_14 = uVar4;
  _memset(&local_5c,0,0x30);
  local_5c = ExportedObject<struct_IServConfig>::vftable;
  local_58 = 0;
  local_54 = 0;
  local_50 = (int *)0x0;
  local_4c = 0;
  local_48 = 0;
  local_34 = 0;
  local_30 = 7;
  local_44 = 0;
  local_8 = 0;
  DVar5 = FUN_10004630((int)&local_5c);
  if (DVar5 == 0) {
    puVar7 = (uint *)(**(code **)(*local_50 + 0x18))(0x2f3,0,uVar4);
    if (puVar7 == (uint *)0x0) {
      piVar6 = FUN_100034b0(local_104,4,0x1005e4bc);
      local_8._0_1_ = 3;
      if ((char)piVar6[0x12] != '\0') {
        FUN_10007f80(piVar6,"failed get SZ_REG_PATH_PRODUCT");
      }
      FUN_10003240((int)local_a4);
      local_8._0_1_ = 4;
    }
    else {
      if ((short)*puVar7 != 0) {
        local_1c = 0;
        local_18 = 7;
        local_2c[0] = (LPCWSTR **)0x0;
        puVar8 = puVar7;
        do {
          uVar4 = *puVar8;
          puVar8 = (uint *)((int)puVar8 + 2);
        } while ((short)uVar4 != 0);
        FUN_10001d40(local_2c,puVar7,(int)puVar8 - ((int)puVar7 + 2) >> 1);
        local_8._0_1_ = 7;
        pwVar11 = L"Install";
        ppppWVar10 = local_2c;
        if (7 < local_18) {
          ppppWVar10 = (LPCWSTR ***)local_2c[0];
        }
        if (*(LPCWSTR)((int)ppppWVar10 + (local_1c + -1) * 2) != L'\\') {
          pwVar11 = L"\\Install";
        }
        pwVar9 = pwVar11;
        do {
          wVar1 = *pwVar9;
          pwVar9 = pwVar9 + 1;
        } while (wVar1 != L'\0');
        FUN_10005d60(local_2c,(uint *)pwVar11,(int)pwVar9 - (int)(pwVar11 + 1) >> 1);
        ppppWVar10 = local_2c;
        if (7 < local_18) {
          ppppWVar10 = (LPCWSTR ***)local_2c[0];
        }
        cVar3 = FUN_10026b80((HKEY)0x80000002,(LPCWSTR)ppppWVar10,L"ProductVersion",param_1);
        if (cVar3 == '\0') {
          piVar6 = FUN_100034b0(local_104,4,0x1005e4bc);
          local_8 = CONCAT31(local_8._1_3_,8);
          cVar3 = (char)piVar6[0x12];
          if (cVar3 != '\0') {
            FUN_100082c0(piVar6,L"failed read ");
            cVar3 = (char)piVar6[0x12];
          }
          ppppWVar10 = local_2c;
          if (7 < local_18) {
            ppppWVar10 = (LPCWSTR ***)local_2c[0];
          }
          if (cVar3 != '\0') {
            FUN_100082c0(piVar6,(short *)ppppWVar10);
          }
          FUN_10003240((int)local_a4);
          local_8._0_1_ = 9;
          local_a4[0] = std::ios_base::vftable;
          std::ios_base::_Ios_base_dtor((ios_base *)local_a4);
        }
        if (7 < local_18) {
          ppppWVar10 = (LPCWSTR ***)local_2c[0];
          if ((0xfff < local_18 * 2 + 2) &&
             (ppppWVar10 = (LPCWSTR ***)local_2c[0][-1],
             0x1f < (uint)((int)local_2c[0] + (-4 - (int)ppppWVar10)))) {
            FUN_10032f7f();
            pcVar2 = (code *)swi(3);
            (*pcVar2)();
            return;
          }
          FUN_1002e346(ppppWVar10);
        }
        local_1c = 0;
        local_18 = 7;
        local_2c[0] = (LPCWSTR **)((uint)local_2c[0] & 0xffff0000);
        goto LAB_100043e0;
      }
      piVar6 = FUN_100034b0(local_104,4,0x1005e4bc);
      local_8._0_1_ = 5;
      if ((char)piVar6[0x12] != '\0') {
        FUN_10007f80(piVar6,"empty value for SZ_REG_PATH_PRODUCT");
      }
      FUN_10003240((int)local_a4);
      local_8._0_1_ = 6;
    }
  }
  else {
    piVar6 = FUN_100034b0(local_104,4,0x1005e4bc);
    local_8._0_1_ = 1;
    if (((char)piVar6[0x12] != '\0') &&
       (FUN_10007f80(piVar6,"failed load IServConfig.dll, err="), (char)piVar6[0x12] != '\0')) {
      FUN_10006730(piVar6,DVar5);
    }
    FUN_10003240((int)local_a4);
    local_8._0_1_ = 2;
  }
  local_a4[0] = std::ios_base::vftable;
  std::ios_base::_Ios_base_dtor((ios_base *)local_a4);
LAB_100043e0:
  FUN_10004750(&local_5c);
  ExceptionList = local_10;
  FUN_1002e315(local_14 ^ (uint)&stack0xfffffffc);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_10004410 @ 10004410