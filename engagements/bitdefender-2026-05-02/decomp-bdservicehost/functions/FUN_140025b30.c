longlong * FUN_140025b30(longlong *param_1,longlong *param_2)

{
  ulonglong uVar1;
  longlong lVar2;
  
  *param_2 = 0;
  param_2[1] = 0;
  lVar2 = param_1[1];
  *param_2 = *param_1;
  param_2[1] = lVar2;
  uVar1 = param_2[1] - 1;
  if (param_2[1] == 0) {
    *param_2 = *param_2 - ((~uVar1 >> 5) * 4 + 4);
    param_2[1] = (ulonglong)((uint)uVar1 & 0x1f);
    return param_2;
  }
  *param_2 = *param_2 + (uVar1 >> 5) * 4;
  param_2[1] = (ulonglong)((uint)uVar1 & 0x1f);
  return param_2;
}


// FUNCTION_END

// FUNCTION_START: FUN_140025b90 @ 140025b90