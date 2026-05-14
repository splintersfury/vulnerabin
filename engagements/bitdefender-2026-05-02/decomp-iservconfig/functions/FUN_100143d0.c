undefined4 * __fastcall FUN_100143d0(undefined4 *param_1,undefined4 *param_2)

{
  undefined4 uVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  
  uVar1 = param_2[1];
  *param_1 = *param_2;
  param_1[1] = uVar1;
  param_1[2] = 0;
  param_1[6] = 0;
  param_1[7] = 0;
  uVar1 = param_2[3];
  uVar2 = param_2[4];
  uVar3 = param_2[5];
  param_1[2] = param_2[2];
  param_1[3] = uVar1;
  param_1[4] = uVar2;
  param_1[5] = uVar3;
  *(undefined8 *)(param_1 + 6) = *(undefined8 *)(param_2 + 6);
  param_2[6] = 0;
  param_2[7] = 0xf;
  *(undefined1 *)(param_2 + 2) = 0;
  return param_1;
}


// FUNCTION_END

// FUNCTION_START: FUN_10014420 @ 10014420