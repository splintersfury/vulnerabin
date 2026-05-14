void FUN_14000e410(undefined8 *param_1,ulonglong param_2,undefined8 param_3)

{
  ulonglong uVar1;
  ulonglong uVar2;
  ulonglong uVar3;
  undefined2 *puVar4;
  undefined8 *puVar5;
  
  uVar1 = param_1[2];
  if (param_2 <= uVar1) {
    puVar5 = param_1;
    if (7 < (ulonglong)param_1[3]) {
      puVar5 = (undefined8 *)*param_1;
    }
    param_1[2] = param_2;
    *(undefined2 *)((longlong)puVar5 + param_2 * 2) = 0;
    return;
  }
  uVar3 = param_2 - uVar1;
  if (param_1[3] - uVar1 < uVar3) {
    FUN_140013620(param_1,uVar3,param_3,uVar3,(short)param_3);
    return;
  }
  param_1[2] = param_2;
  if (7 < (ulonglong)param_1[3]) {
    param_1 = (undefined8 *)*param_1;
  }
  puVar4 = (undefined2 *)((longlong)param_1 + uVar1 * 2);
  uVar2 = uVar3;
  if (uVar3 != 0) {
    for (; uVar2 != 0; uVar2 = uVar2 - 1) {
      *puVar4 = (short)param_3;
      puVar4 = puVar4 + 1;
    }
  }
  *(undefined2 *)((longlong)param_1 + (uVar1 + uVar3) * 2) = 0;
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_14000e4a0 @ 14000e4a0