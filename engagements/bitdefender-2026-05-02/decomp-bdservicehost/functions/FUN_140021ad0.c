longlong * FUN_140021ad0(longlong *param_1,longlong *param_2,undefined8 param_3)

{
  ulonglong uVar1;
  ulonglong uVar2;
  longlong lVar3;
  longlong *plVar4;
  
  uVar1 = param_2[2];
  uVar2 = param_2[3];
  if (uVar1 < uVar2) {
    param_2[2] = uVar1 + 1;
    plVar4 = param_2;
    if (0xf < uVar2) {
      plVar4 = (longlong *)*param_2;
    }
    *(undefined2 *)((longlong)plVar4 + uVar1) = 0x2e;
  }
  else {
    FUN_1400137e0(param_2,uVar2,param_3,0x2e);
  }
  *param_1 = 0;
  param_1[2] = 0;
  param_1[3] = 0;
  lVar3 = param_2[1];
  *param_1 = *param_2;
  param_1[1] = lVar3;
  lVar3 = param_2[3];
  param_1[2] = param_2[2];
  param_1[3] = lVar3;
  param_2[2] = 0;
  *(undefined1 *)param_2 = 0;
  param_2[3] = 0xf;
  return param_1;
}


// FUNCTION_END

// FUNCTION_START: FUN_140021b50 @ 140021b50