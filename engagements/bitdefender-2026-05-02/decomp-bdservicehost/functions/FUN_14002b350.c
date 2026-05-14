void FUN_14002b350(undefined8 *param_1,SC_HANDLE param_2)

{
  undefined8 uVar1;
  undefined8 uVar2;
  undefined8 uVar3;
  char cVar4;
  BOOL BVar5;
  DWORD DVar6;
  undefined1 auStack_a8 [32];
  undefined8 *local_88;
  undefined1 local_80 [24];
  undefined8 uStack_68;
  DWORD local_60;
  undefined4 uStack_5c;
  undefined **ppuStack_58;
  undefined1 local_50;
  undefined7 uStack_4f;
  undefined8 uStack_48;
  undefined8 local_40;
  undefined8 uStack_38;
  char local_30;
  ulonglong local_28;
  
  local_28 = DAT_14007a060 ^ (ulonglong)auStack_a8;
  local_88 = param_1;
  BVar5 = QueryServiceStatus(param_2,(LPSERVICE_STATUS)local_80);
  if (BVar5 == 0) {
    DVar6 = GetLastError();
    if (DVar6 == 0) goto LAB_14002b3ed;
    local_80._0_8_ = 0;
    local_80._16_4_ = 0;
    local_80._20_4_ = 0;
    uStack_68 = 0xf;
    FUN_1400106a0((longlong *)local_80,(undefined8 *)"query_service_status failed",0x1b);
    local_60 = DVar6;
LAB_14002b3c2:
    ppuStack_58 = &PTR_vftable_14007ad08;
    *param_1 = CONCAT44(uStack_5c,local_60);
    param_1[1] = &PTR_vftable_14007ad08;
    param_1[2] = local_80._0_8_;
    param_1[3] = local_80._8_8_;
    param_1[4] = local_80._16_8_;
    param_1[5] = uStack_68;
    *(undefined1 *)(param_1 + 6) = 1;
  }
  else {
LAB_14002b3ed:
    if (SUB84(local_80._0_8_,4) != 1) {
      if (SUB84(local_80._0_8_,4) != 3) {
        FUN_14002aaa0((undefined8 *)&local_60,param_2,1);
        uVar3 = uStack_38;
        uVar2 = local_40;
        if (local_30 != '\0') {
          uVar1 = CONCAT71(uStack_4f,local_50);
          local_40 = _DAT_14006e190;
          uStack_38 = _UNK_14006e198;
          local_50 = 0;
          *param_1 = CONCAT44(uStack_5c,local_60);
          param_1[1] = ppuStack_58;
          param_1[2] = uVar1;
          param_1[3] = uStack_48;
          param_1[4] = uVar2;
          param_1[5] = uVar3;
          *(undefined1 *)(param_1 + 6) = 1;
          FUN_14002d150((longlong)&local_60);
          goto LAB_14002b4b6;
        }
        FUN_14002d150((longlong)&local_60);
      }
      cVar4 = FUN_14002c1f0(param_2,0xffffffff);
      if (cVar4 == '\0') {
        local_80._0_8_ = 0;
        local_80._16_4_ = 0;
        local_80._20_4_ = 0;
        uStack_68 = 0xf;
        FUN_1400106a0((longlong *)local_80,(undefined8 *)"wait_service_to_stop failed",0x1b);
        local_60 = 0x5b4;
        goto LAB_14002b3c2;
      }
    }
    *param_1 = 0;
    param_1[1] = 0;
    param_1[2] = 0;
    param_1[3] = 0;
    param_1[4] = 0;
    param_1[5] = 0;
    param_1[6] = 0;
    *(undefined1 *)(param_1 + 6) = 0;
  }
LAB_14002b4b6:
  FUN_14002f160(local_28 ^ (ulonglong)auStack_a8);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_14002b4e0 @ 14002b4e0