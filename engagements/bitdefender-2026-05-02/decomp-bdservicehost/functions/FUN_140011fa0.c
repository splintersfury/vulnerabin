undefined8 *
FUN_140011fa0(undefined8 *param_1,undefined8 *param_2,undefined8 *param_3,undefined8 param_4)

{
  longlong lVar1;
  undefined8 uVar2;
  ulonglong uVar3;
  ulonglong uVar4;
  undefined8 *puVar5;
  
  uVar3 = 0xffffffffffffffff;
  do {
    uVar3 = uVar3 + 1;
  } while (*(char *)((longlong)param_2 + uVar3) != '\0');
  lVar1 = param_3[2];
  if ((ulonglong)(param_3[3] - lVar1) < uVar3) {
    param_3 = FUN_140014ae0(param_3,uVar3,lVar1,param_4,param_2,uVar3);
  }
  else {
    param_3[2] = lVar1 + uVar3;
    puVar5 = param_3;
    if (0xf < (ulonglong)param_3[3]) {
      puVar5 = (undefined8 *)*param_3;
    }
    uVar4 = uVar3;
    if (((puVar5 < (undefined8 *)(uVar3 + (longlong)param_2)) &&
        (param_2 <= (undefined8 *)((longlong)puVar5 + lVar1))) && (uVar4 = 0, param_2 < puVar5)) {
      uVar4 = (longlong)puVar5 - (longlong)param_2;
    }
    FUN_1400316b0((undefined8 *)((longlong)puVar5 + uVar3),puVar5,lVar1 + 1);
    FUN_1400316b0(puVar5,param_2,uVar4);
    FUN_1400316b0((undefined8 *)((longlong)puVar5 + uVar4),
                  (undefined8 *)(uVar4 + uVar3 + (longlong)param_2),uVar3 - uVar4);
  }
  *param_1 = 0;
  param_1[2] = 0;
  param_1[3] = 0;
  uVar2 = param_3[1];
  *param_1 = *param_3;
  param_1[1] = uVar2;
  uVar2 = param_3[3];
  param_1[2] = param_3[2];
  param_1[3] = uVar2;
  param_3[2] = 0;
  *(undefined1 *)param_3 = 0;
  param_3[3] = 0xf;
  return param_1;
}


// FUNCTION_END

// FUNCTION_START: FUN_1400120c0 @ 1400120c0