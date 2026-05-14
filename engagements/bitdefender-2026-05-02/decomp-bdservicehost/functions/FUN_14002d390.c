undefined8 * FUN_14002d390(undefined8 *param_1,undefined8 *param_2)

{
  undefined8 uVar1;
  
  uVar1 = param_2[1];
  *param_1 = *param_2;
  param_1[1] = uVar1;
  param_1[2] = 0;
  param_1[4] = 0;
  param_1[5] = 0;
  uVar1 = param_2[3];
  param_1[2] = param_2[2];
  param_1[3] = uVar1;
  uVar1 = param_2[5];
  param_1[4] = param_2[4];
  param_1[5] = uVar1;
  param_2[4] = 0;
  *(undefined1 *)(param_2 + 2) = 0;
  param_2[5] = 0xf;
  return param_1;
}


// FUNCTION_END

// FUNCTION_START: FUN_14002d3d0 @ 14002d3d0