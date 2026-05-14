ulonglong FUN_14001d6e0(undefined8 param_1,undefined8 param_2,longlong param_3,longlong param_4,
                       ulonglong param_5)

{
  ulonglong uVar1;
  
  uVar1 = param_4 - param_3;
  if (0x7fffffff < (longlong)uVar1) {
    uVar1 = 0x7fffffff;
  }
  if (uVar1 < param_5) {
    param_5 = uVar1;
  }
  return param_5 & 0xffffffff;
}


// FUNCTION_END

// FUNCTION_START: FUN_14001d700 @ 14001d700