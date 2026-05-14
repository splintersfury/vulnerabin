undefined4 * __fastcall FUN_10014620(undefined4 *param_1,undefined4 param_2,uint *param_3)

{
  uint uVar1;
  uint *puVar2;
  undefined4 local_20;
  undefined4 uStack_1c;
  undefined4 uStack_18;
  undefined4 uStack_14;
  undefined4 local_10;
  undefined4 uStack_c;
  undefined4 *local_8;
  
  local_20 = 0;
  local_10 = 0;
  uStack_c = 0xf;
  puVar2 = param_3;
  do {
    uVar1 = *puVar2;
    puVar2 = (uint *)((int)puVar2 + 1);
  } while ((char)uVar1 != '\0');
  local_8 = param_1;
  FUN_10008e70(&local_20,param_3,(int)puVar2 - ((int)param_3 + 1));
  *param_1 = param_2;
  param_1[1] = &PTR_vftable_10069ab8;
  param_1[2] = 0;
  param_1[6] = 0;
  param_1[7] = 0;
  param_1[2] = local_20;
  param_1[3] = uStack_1c;
  param_1[4] = uStack_18;
  param_1[5] = uStack_14;
  *(ulonglong *)(param_1 + 6) = CONCAT44(uStack_c,local_10);
  return param_1;
}


// FUNCTION_END

// FUNCTION_START: FUN_100146a0 @ 100146a0