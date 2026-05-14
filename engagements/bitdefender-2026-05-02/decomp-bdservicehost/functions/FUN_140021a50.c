longlong * FUN_140021a50(longlong *param_1,longlong *param_2,undefined8 *param_3)

{
  ulonglong *puVar1;
  longlong lVar2;
  longlong *plVar3;
  
  puVar1 = param_3 + 2;
  if (0xf < (ulonglong)param_3[3]) {
    param_3 = (undefined8 *)*param_3;
  }
  plVar3 = FUN_140010800(param_2,param_3,*puVar1);
  *param_1 = 0;
  param_1[2] = 0;
  param_1[3] = 0;
  lVar2 = plVar3[1];
  *param_1 = *plVar3;
  param_1[1] = lVar2;
  lVar2 = plVar3[3];
  param_1[2] = plVar3[2];
  param_1[3] = lVar2;
  plVar3[2] = 0;
  plVar3[3] = 0xf;
  *(undefined1 *)plVar3 = 0;
  return param_1;
}


// FUNCTION_END

// FUNCTION_START: FUN_140021ab0 @ 140021ab0