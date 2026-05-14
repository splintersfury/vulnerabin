undefined8 * FUN_14002b740(undefined8 *param_1,SC_HANDLE param_2,DWORD param_3)

{
  BOOL BVar1;
  DWORD DVar2;
  longlong local_70;
  undefined8 uStack_68;
  undefined8 local_60;
  undefined8 uStack_58;
  undefined4 uStack_4c;
  
  BVar1 = ChangeServiceConfigW
                    (param_2,0xffffffff,param_3,0xffffffff,(LPCWSTR)0x0,(LPCWSTR)0x0,(LPDWORD)0x0,
                     (LPCWSTR)0x0,(LPCWSTR)0x0,(LPCWSTR)0x0,(LPCWSTR)0x0);
  if (BVar1 != 1) {
    DVar2 = GetLastError();
    local_70 = 0;
    local_60 = 0;
    uStack_58 = 0xf;
    FUN_1400106a0(&local_70,(undefined8 *)"ChangeServiceConfigW failed",0x1b);
    *param_1 = CONCAT44(uStack_4c,DVar2);
    param_1[1] = &PTR_vftable_14007ad08;
    param_1[2] = local_70;
    param_1[3] = uStack_68;
    param_1[4] = local_60;
    param_1[5] = uStack_58;
    *(undefined1 *)(param_1 + 6) = 1;
    return param_1;
  }
  *param_1 = 0;
  param_1[1] = 0;
  param_1[2] = 0;
  param_1[3] = 0;
  param_1[4] = 0;
  param_1[5] = 0;
  param_1[6] = 0;
  *(undefined1 *)(param_1 + 6) = 0;
  return param_1;
}


// FUNCTION_END

// FUNCTION_START: FUN_14002b840 @ 14002b840