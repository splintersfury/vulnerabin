void FUN_14002aaa0(undefined8 *param_1,SC_HANDLE param_2,DWORD param_3)

{
  BOOL BVar1;
  DWORD DVar2;
  undefined1 auStack_98 [32];
  undefined8 *local_78;
  longlong local_70;
  undefined8 uStack_68;
  undefined8 local_60;
  undefined8 uStack_58;
  undefined1 local_50 [48];
  ulonglong local_20;
  
  local_20 = DAT_14007a060 ^ (ulonglong)auStack_98;
  local_78 = param_1;
  BVar1 = ControlService(param_2,param_3,(LPSERVICE_STATUS)local_50);
  if (BVar1 == 0) {
    DVar2 = GetLastError();
    uStack_58 = 0xf;
    local_70 = 0;
    local_60 = 0;
    FUN_1400106a0(&local_70,(undefined8 *)"ControlService failed",0x15);
    local_50._8_8_ = &PTR_vftable_14007ad08;
    *param_1 = CONCAT44(local_50._4_4_,DVar2);
    param_1[1] = &PTR_vftable_14007ad08;
    param_1[2] = local_70;
    param_1[3] = uStack_68;
    param_1[4] = local_60;
    param_1[5] = uStack_58;
    *(undefined1 *)(param_1 + 6) = 1;
    local_50._0_4_ = DVar2;
  }
  else {
    *param_1 = 0;
    param_1[1] = 0;
    param_1[2] = 0;
    param_1[3] = 0;
    param_1[4] = 0;
    param_1[5] = 0;
    param_1[6] = 0;
    *(undefined1 *)(param_1 + 6) = 0;
  }
  FUN_14002f160(local_20 ^ (ulonglong)auStack_98);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_14002aba0 @ 14002aba0