void FUN_140001ab0(undefined8 *param_1,longlong param_2)

{
  undefined1 auStack_48 [32];
  longlong local_28;
  undefined1 local_20;
  ulonglong local_18;
  
  local_18 = DAT_14007a060 ^ (ulonglong)auStack_48;
  local_20 = 1;
  *param_1 = std::exception::vftable;
  param_1[1] = 0;
  param_1[2] = 0;
  local_28 = param_2;
  __std_exception_copy(&local_28,param_1 + 1);
  *param_1 = std::runtime_error::vftable;
  FUN_14002f160(local_18 ^ (ulonglong)auStack_48);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_140001b20 @ 140001b20