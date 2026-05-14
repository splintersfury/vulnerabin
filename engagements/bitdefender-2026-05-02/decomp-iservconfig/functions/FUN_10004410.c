void __fastcall FUN_10004410(undefined4 *param_1)

{
  uint uVar1;
  DWORD DVar2;
  int *piVar3;
  uint *puVar4;
  uint *puVar5;
  undefined4 *puVar6;
  int local_ec [24];
  undefined **local_8c [18];
  undefined **local_44;
  undefined4 local_40;
  undefined4 local_3c;
  int *local_38;
  undefined4 local_34;
  undefined4 local_30;
  undefined4 local_2c;
  undefined4 local_1c;
  undefined4 local_18;
  uint local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_1004dce3;
  local_10 = ExceptionList;
  uVar1 = DAT_10069054 ^ (uint)&stack0xfffffffc;
  ExceptionList = &local_10;
  local_14 = uVar1;
  _memset(&local_44,0,0x30);
  local_44 = ExportedObject<struct_IServConfig>::vftable;
  local_40 = 0;
  local_3c = 0;
  local_38 = (int *)0x0;
  local_34 = 0;
  local_30 = 0;
  local_1c = 0;
  local_18 = 7;
  local_2c = 0;
  local_8 = 0;
  DVar2 = FUN_10004630((int)&local_44);
  if (DVar2 == 0) {
    puVar4 = (uint *)(**(code **)(*local_38 + 0x18))(0x2f3,0,uVar1);
    if ((puVar4 != (uint *)0x0) && ((short)*puVar4 != 0)) {
      puVar5 = puVar4;
      do {
        uVar1 = *puVar5;
        puVar5 = (uint *)((int)puVar5 + 2);
      } while ((short)uVar1 != 0);
      FUN_10001d40(param_1,puVar4,(int)puVar5 - ((int)puVar4 + 2) >> 1);
      puVar6 = param_1;
      if (7 < (uint)param_1[5]) {
        puVar6 = (undefined4 *)*param_1;
      }
      if (*(short *)((int)puVar6 + param_1[4] * 2 + -2) != 0x5c) {
        FUN_10005b60(param_1,0x5c);
      }
      FUN_10005d60(param_1,(uint *)L"bdec\\fields",0xb);
      goto LAB_100045c0;
    }
    piVar3 = FUN_100034b0(local_ec,4,0x1005e5f4);
    local_8._0_1_ = 3;
    if ((char)piVar3[0x12] != '\0') {
      FUN_10007f80(piVar3,"failed get SZ_REG_PATH_PRODUCT");
    }
    FUN_10003240((int)local_8c);
    local_8 = CONCAT31(local_8._1_3_,4);
  }
  else {
    piVar3 = FUN_100034b0(local_ec,4,0x1005e5f4);
    local_8._0_1_ = 1;
    if ((char)piVar3[0x12] != '\0') {
      FUN_10007f80(piVar3,"failed load IServConfig.dll, err=");
      if ((char)piVar3[0x12] != '\0') {
        FUN_10006730(piVar3,DVar2);
      }
    }
    FUN_10003240((int)local_8c);
    local_8 = CONCAT31(local_8._1_3_,2);
  }
  local_8c[0] = std::ios_base::vftable;
  std::ios_base::_Ios_base_dtor((ios_base *)local_8c);
LAB_100045c0:
  FUN_10004750(&local_44);
  ExceptionList = local_10;
  FUN_1002e315(local_14 ^ (uint)&stack0xfffffffc);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_100045f0 @ 100045f0