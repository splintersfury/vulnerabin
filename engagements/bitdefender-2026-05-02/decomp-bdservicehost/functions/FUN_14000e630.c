undefined8 * FUN_14000e630(undefined8 *param_1,undefined8 *param_2,ulonglong param_3)

{
  longlong lVar1;
  undefined8 *puVar2;
  
  lVar1 = param_1[2];
  if (param_3 <= (ulonglong)(param_1[3] - lVar1)) {
    param_1[2] = lVar1 + param_3;
    puVar2 = param_1;
    if (7 < (ulonglong)param_1[3]) {
      puVar2 = (undefined8 *)*param_1;
    }
    FUN_1400316b0((undefined8 *)((longlong)puVar2 + lVar1 * 2),param_2,param_3 * 2);
    *(undefined2 *)((longlong)puVar2 + (lVar1 + param_3) * 2) = 0;
    return param_1;
  }
  puVar2 = FUN_1400131d0(param_1,param_3,param_3,param_2,param_3);
  return puVar2;
}


// FUNCTION_END

// FUNCTION_START: FUN_14000e6b0 @ 14000e6b0