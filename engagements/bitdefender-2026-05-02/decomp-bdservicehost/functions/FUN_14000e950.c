longlong * FUN_14000e950(longlong *param_1,undefined8 *param_2)

{
  ulonglong uVar1;
  
  param_1[3] = 0xf;
  *param_1 = 0;
  param_1[2] = 0;
  uVar1 = 0xffffffffffffffff;
  do {
    uVar1 = uVar1 + 1;
  } while (*(char *)((longlong)param_2 + uVar1) != '\0');
  FUN_1400106a0(param_1,param_2,uVar1);
  return param_1;
}


// FUNCTION_END

// FUNCTION_START: FUN_14000e990 @ 14000e990