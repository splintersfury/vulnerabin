longlong * FUN_1400219f0(longlong *param_1,longlong *param_2,undefined8 *param_3)

{
  longlong lVar1;
  longlong *plVar2;
  ulonglong uVar3;
  
  uVar3 = 0xffffffffffffffff;
  do {
    uVar3 = uVar3 + 1;
  } while (*(char *)((longlong)param_3 + uVar3) != '\0');
  plVar2 = FUN_140010800(param_2,param_3,uVar3);
  *param_1 = 0;
  param_1[2] = 0;
  param_1[3] = 0;
  lVar1 = plVar2[1];
  *param_1 = *plVar2;
  param_1[1] = lVar1;
  lVar1 = plVar2[3];
  param_1[2] = plVar2[2];
  param_1[3] = lVar1;
  plVar2[2] = 0;
  plVar2[3] = 0xf;
  *(undefined1 *)plVar2 = 0;
  return param_1;
}


// FUNCTION_END

// FUNCTION_START: FUN_140021a50 @ 140021a50