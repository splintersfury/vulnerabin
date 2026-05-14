void FUN_14002bba0(undefined8 *param_1,SC_HANDLE param_2,undefined4 param_3)

{
  BOOL BVar1;
  DWORD DVar2;
  undefined1 auStack_a8 [32];
  longlong local_88;
  undefined8 uStack_80;
  undefined8 local_78;
  undefined8 uStack_70;
  DWORD local_60;
  undefined4 uStack_5c;
  undefined **ppuStack_58;
  undefined4 local_30;
  undefined4 uStack_2c;
  ulonglong local_28;
  
  local_28 = DAT_14007a060 ^ (ulonglong)auStack_a8;
  _local_30 = CONCAT44((int)((ulonglong)param_1 >> 0x20),param_3);
  BVar1 = ChangeServiceConfig2W(param_2,0xc,&local_30);
  if (BVar1 == 1) {
    *param_1 = 0;
    param_1[1] = 0;
    param_1[2] = 0;
    param_1[3] = 0;
    param_1[4] = 0;
    param_1[5] = 0;
    param_1[6] = 0;
    *(undefined1 *)(param_1 + 6) = 0;
  }
  else {
    DVar2 = GetLastError();
    uStack_70 = 0xf;
    local_88 = 0;
    local_78 = 0;
    FUN_1400106a0(&local_88,(undefined8 *)"ChangeServiceConfig2W failed",0x1c);
    ppuStack_58 = &PTR_vftable_14007ad08;
    *param_1 = CONCAT44(uStack_5c,DVar2);
    param_1[1] = &PTR_vftable_14007ad08;
    param_1[2] = local_88;
    param_1[3] = uStack_80;
    param_1[4] = local_78;
    param_1[5] = uStack_70;
    *(undefined1 *)(param_1 + 6) = 1;
    local_60 = DVar2;
  }
  FUN_14002f160(local_28 ^ (ulonglong)auStack_a8);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_14002bca0 @ 14002bca0