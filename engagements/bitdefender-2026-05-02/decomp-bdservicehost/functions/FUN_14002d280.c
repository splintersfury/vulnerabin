undefined4 * FUN_14002d280(undefined4 *param_1,undefined8 param_2,undefined8 *param_3)

{
  ulonglong uVar1;
  longlong local_30;
  undefined8 uStack_28;
  undefined8 local_20;
  undefined8 uStack_18;
  
  local_30 = 0;
  local_20 = 0;
  uStack_18 = 0xf;
  uVar1 = 0xffffffffffffffff;
  do {
    uVar1 = uVar1 + 1;
  } while (*(char *)((longlong)param_3 + uVar1) != '\0');
  FUN_1400106a0(&local_30,param_3,uVar1);
  *param_1 = 0x5b4;
  *(undefined ***)(param_1 + 2) = &PTR_vftable_14007ad08;
  *(longlong *)(param_1 + 4) = local_30;
  *(undefined8 *)(param_1 + 6) = uStack_28;
  *(undefined8 *)(param_1 + 8) = local_20;
  *(undefined8 *)(param_1 + 10) = uStack_18;
  return param_1;
}


// FUNCTION_END

// FUNCTION_START: FUN_14002d300 @ 14002d300