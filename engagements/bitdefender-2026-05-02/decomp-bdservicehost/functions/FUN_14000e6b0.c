longlong * FUN_14000e6b0(longlong *param_1,longlong *param_2)

{
  code *pcVar1;
  longlong lVar2;
  longlong *plVar3;
  
  if (param_1 != param_2) {
    if (7 < (ulonglong)param_1[3]) {
      if ((0xfff < param_1[3] * 2 + 2U) && (0x1f < (*param_1 - *(longlong *)(*param_1 + -8)) - 8U))
      {
        FUN_140035d28();
        pcVar1 = (code *)swi(3);
        plVar3 = (longlong *)(*pcVar1)();
        return plVar3;
      }
      FUN_14002f180();
    }
    param_1[3] = 7;
    param_1[2] = 0;
    *(undefined2 *)param_1 = 0;
    lVar2 = param_2[1];
    *param_1 = *param_2;
    param_1[1] = lVar2;
    lVar2 = param_2[3];
    param_1[2] = param_2[2];
    param_1[3] = lVar2;
    param_2[2] = 0;
    param_2[3] = 7;
    *(undefined2 *)param_2 = 0;
  }
  return param_1;
}


// FUNCTION_END

// FUNCTION_START: FUN_14000e750 @ 14000e750