void __thiscall FUN_1000c9d0(void *this,int *param_1,ushort *param_2)

{
  ushort uVar1;
  undefined1 uVar2;
  char cVar3;
  int *piVar4;
  uint uVar5;
  wchar_t *pwVar6;
  ushort *puVar7;
  wchar_t *pwVar8;
  bool bVar9;
  int local_4d0 [24];
  undefined **local_470 [18];
  undefined1 local_428 [1044];
  uint local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_1004e6dc;
  local_10 = ExceptionList;
  local_14 = DAT_10069054 ^ (uint)&stack0xfffffffc;
  ExceptionList = &local_10;
  FUN_1000c210(local_428,L"ProductInfo::GetString");
  local_8 = 0;
  piVar4 = FUN_100034b0(local_4d0,0x10,0x1005ed00);
  local_8._0_1_ = 1;
  if ((char)piVar4[0x12] != '\0') {
    FUN_10007f80(piVar4,"id=");
    if ((char)piVar4[0x12] != '\0') {
      FUN_1001a980(piVar4,param_1);
    }
  }
  FUN_10003240((int)local_470);
  local_8._0_1_ = 2;
  local_470[0] = std::ios_base::vftable;
  std::ios_base::_Ios_base_dtor((ios_base *)local_470);
  local_8._0_1_ = 0;
  uVar2 = (undefined1)local_8;
  local_8._0_1_ = 0;
  if (param_2 != (ushort *)0x0) {
    puVar7 = &DAT_1005ecd0;
    do {
      uVar1 = *param_2;
      bVar9 = uVar1 < *puVar7;
      if (uVar1 != *puVar7) {
LAB_1000cabc:
        uVar5 = -(uint)bVar9 | 1;
        goto LAB_1000cac1;
      }
      if (uVar1 == 0) break;
      uVar1 = param_2[1];
      bVar9 = uVar1 < puVar7[1];
      if (uVar1 != puVar7[1]) goto LAB_1000cabc;
      param_2 = param_2 + 2;
      puVar7 = puVar7 + 2;
    } while (uVar1 != 0);
    uVar5 = 0;
LAB_1000cac1:
    if (uVar5 == 0) {
      piVar4 = FUN_100034b0(local_4d0,0x10,0x1005ed00);
      local_8._0_1_ = 3;
      if ((char)piVar4[0x12] != '\0') {
        FUN_100082c0(piVar4,L"selector=bdec");
      }
      FUN_10003240((int)local_470);
      local_8._0_1_ = 4;
      local_470[0] = std::ios_base::vftable;
      std::ios_base::_Ios_base_dtor((ios_base *)local_470);
      local_8._0_1_ = 0;
      pwVar6 = (wchar_t *)FUN_1000d250(this,(uint)param_1);
      piVar4 = FUN_100034b0(local_4d0,0x10,0x1005ed00);
      local_8 = CONCAT31(local_8._1_3_,5);
      cVar3 = (char)piVar4[0x12];
      if (cVar3 != '\0') {
        FUN_10007f80(piVar4,"value=");
        cVar3 = (char)piVar4[0x12];
      }
      pwVar8 = L"null";
      if (pwVar6 != (wchar_t *)0x0) {
        pwVar8 = pwVar6;
      }
      if (cVar3 != '\0') {
        FUN_100082c0(piVar4,pwVar8);
      }
      FUN_10003240((int)local_470);
      local_8 = CONCAT31(local_8._1_3_,6);
      goto LAB_1000cbe7;
    }
  }
  local_8._0_1_ = uVar2;
  pwVar6 = (wchar_t *)FUN_1000cfc0(this,param_1);
  piVar4 = FUN_100034b0(local_4d0,0x10,0x1005ed00);
  local_8 = CONCAT31(local_8._1_3_,7);
  cVar3 = (char)piVar4[0x12];
  if (cVar3 != '\0') {
    FUN_10007f80(piVar4,"value=");
    cVar3 = (char)piVar4[0x12];
  }
  pwVar8 = L"null";
  if (pwVar6 != (wchar_t *)0x0) {
    pwVar8 = pwVar6;
  }
  if (cVar3 != '\0') {
    FUN_100082c0(piVar4,pwVar8);
  }
  FUN_10003240((int)local_470);
  local_8 = CONCAT31(local_8._1_3_,8);
LAB_1000cbe7:
  local_470[0] = std::ios_base::vftable;
  std::ios_base::_Ios_base_dtor((ios_base *)local_470);
  FUN_1000c320((int)local_428);
  ExceptionList = local_10;
  FUN_1002e315(local_14 ^ (uint)&stack0xfffffffc);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_1000cc30 @ 1000cc30