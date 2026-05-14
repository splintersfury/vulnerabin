void __fastcall FUN_10003650(undefined4 param_1,uint *******param_2)

{
  uint uVar1;
  ios_base *piVar2;
  DWORD DVar3;
  int *piVar4;
  uint *puVar5;
  uint *puVar6;
  short *psVar7;
  int local_194 [24];
  undefined **local_134 [18];
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
  puStack_c = &LAB_1004dbcf;
  local_10 = ExceptionList;
  uVar1 = DAT_10069054 ^ (uint)&stack0xfffffffc;
  ExceptionList = &local_10;
  local_14 = uVar1;
  switch(param_1) {
  case 0:
    FUN_100247f0((short *)param_2);
    break;
  case 1:
    FUN_10003ad0(param_2);
    break;
  case 2:
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
    DVar3 = FUN_10004630((int)&local_44);
    if (DVar3 == 0) {
      puVar5 = (uint *)(**(code **)(*local_38 + 0x18))(0,0);
      if (puVar5 != (uint *)0x0) {
        psVar7 = (short *)((int)puVar5 + 2);
        puVar6 = puVar5;
        do {
          uVar1 = *puVar6;
          puVar6 = (uint *)((int)puVar6 + 2);
        } while ((short)uVar1 != 0);
LAB_10003810:
        FUN_10001d40(param_2,puVar5,(int)puVar6 - (int)psVar7 >> 1);
        FUN_10004750(&local_44);
        break;
      }
      piVar4 = FUN_100034b0(local_194,4,0x1005e47c);
      local_8._0_1_ = 3;
      if ((char)piVar4[0x12] != '\0') {
        FUN_10007f80(piVar4,"failed get SZ_PRODUCT_NAME");
      }
      FUN_10003240((int)local_134);
      local_8 = CONCAT31(local_8._1_3_,4);
      piVar2 = (ios_base *)local_134;
      local_134[0] = std::ios_base::vftable;
    }
    else {
      piVar4 = FUN_100034b0(local_ec,4,0x1005e47c);
      local_8._0_1_ = 1;
      if (((char)piVar4[0x12] != '\0') &&
         (FUN_10007f80(piVar4,"failed load IServConfig.dll, err="), (char)piVar4[0x12] != '\0')) {
        FUN_10006730(piVar4,DVar3);
      }
      FUN_10003240((int)local_8c);
      local_8 = CONCAT31(local_8._1_3_,2);
LAB_10003760:
      local_8c[0] = std::ios_base::vftable;
      piVar2 = (ios_base *)local_8c;
    }
    goto LAB_10003770;
  case 3:
    FUN_100040e0(param_2);
    break;
  case 4:
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
    local_8 = 5;
    DVar3 = FUN_10004630((int)&local_44);
    if (DVar3 == 0) {
      puVar5 = (uint *)(**(code **)(*local_38 + 0x18))(0x2f1,0);
      if (puVar5 != (uint *)0x0) {
        psVar7 = (short *)((int)puVar5 + 2);
        puVar6 = puVar5;
        do {
          uVar1 = *puVar6;
          puVar6 = (uint *)((int)puVar6 + 2);
        } while ((short)uVar1 != 0);
        goto LAB_10003810;
      }
      piVar4 = FUN_100034b0(local_ec,4,0x1005e588);
      local_8._0_1_ = 8;
      if ((char)piVar4[0x12] != '\0') {
        FUN_10007f80(piVar4,"failed get SZ_LANG");
      }
      FUN_10003240((int)local_8c);
      local_8 = CONCAT31(local_8._1_3_,9);
      goto LAB_10003760;
    }
    piVar4 = FUN_100034b0(local_194,4,0x1005e588);
    local_8._0_1_ = 6;
    if (((char)piVar4[0x12] != '\0') &&
       (FUN_10007f80(piVar4,"failed load IServConfig.dll, err="), (char)piVar4[0x12] != '\0')) {
      FUN_10006730(piVar4,DVar3);
    }
    FUN_10003240((int)local_134);
    local_8 = CONCAT31(local_8._1_3_,7);
    piVar2 = (ios_base *)local_134;
    local_134[0] = std::ios_base::vftable;
    goto LAB_10003770;
  case 5:
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
    local_8 = 10;
    DVar3 = FUN_10004630((int)&local_44);
    if (DVar3 == 0) {
      puVar5 = (uint *)(**(code **)(*local_38 + 0x18))(2,0,uVar1);
      if (puVar5 != (uint *)0x0) {
        psVar7 = (short *)((int)puVar5 + 2);
        puVar6 = puVar5;
        do {
          uVar1 = *puVar6;
          puVar6 = (uint *)((int)puVar6 + 2);
        } while ((short)uVar1 != 0);
        goto LAB_10003810;
      }
      piVar4 = FUN_100034b0(local_ec,4,0x1005e5b0);
      local_8._0_1_ = 0xd;
      if ((char)piVar4[0x12] != '\0') {
        FUN_10007f80(piVar4,"failed get SZ_PRODUCT_FULLNAME");
      }
      FUN_10003240((int)local_8c);
      local_8 = CONCAT31(local_8._1_3_,0xe);
      goto LAB_10003760;
    }
    piVar4 = FUN_100034b0(local_194,4,0x1005e5b0);
    local_8._0_1_ = 0xb;
    if (((char)piVar4[0x12] != '\0') &&
       (FUN_10007f80(piVar4,"failed load IServConfig.dll, err="), (char)piVar4[0x12] != '\0')) {
      FUN_10006730(piVar4,DVar3);
    }
    FUN_10003240((int)local_134);
    local_8 = CONCAT31(local_8._1_3_,0xc);
    piVar2 = (ios_base *)local_134;
    local_134[0] = std::ios_base::vftable;
LAB_10003770:
    std::ios_base::_Ios_base_dtor(piVar2);
    FUN_10004750(&local_44);
    break;
  case 6:
    FUN_10004410(param_2);
  }
  ExceptionList = local_10;
  FUN_1002e315(local_14 ^ (uint)&stack0xfffffffc);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_10003ad0 @ 10003ad0

/* WARNING: Type propagation algorithm not settling */