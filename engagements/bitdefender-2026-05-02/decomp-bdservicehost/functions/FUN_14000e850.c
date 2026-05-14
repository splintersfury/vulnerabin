void FUN_14000e850(undefined8 *param_1,ulonglong param_2,undefined8 param_3)

{
  ulonglong *puVar1;
  ulonglong uVar2;
  ulonglong uVar3;
  
  uVar2 = param_1[2];
  puVar1 = param_1 + 2;
  if (param_2 <= uVar2) {
    if (0xf < (ulonglong)param_1[3]) {
      param_1 = (undefined8 *)*param_1;
    }
    *puVar1 = param_2;
    *(undefined1 *)((longlong)param_1 + param_2) = 0;
    return;
  }
  uVar3 = param_2 - uVar2;
  if (uVar3 <= param_1[3] - uVar2) {
    *puVar1 = param_2;
    if (0xf < (ulonglong)param_1[3]) {
      param_1 = (undefined8 *)*param_1;
    }
    FUN_140031e00((undefined1 (*) [16])((longlong)param_1 + uVar2),(byte)param_3,uVar3);
    *(undefined1 *)((longlong)((longlong)param_1 + uVar2) + uVar3) = 0;
    return;
  }
  FUN_140013950(param_1,uVar3,param_3,uVar3,(byte)param_3);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_14000e8f0 @ 14000e8f0