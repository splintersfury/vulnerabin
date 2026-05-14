undefined8 * FUN_14002d66c(undefined8 *param_1,longlong param_2)

{
  longlong local_18;
  undefined1 local_10;
  
  local_10 = 1;
  *param_1 = std::exception::vftable;
  param_1[1] = 0;
  param_1[2] = 0;
  local_18 = param_2;
  __std_exception_copy(&local_18,param_1 + 1);
  *param_1 = std::out_of_range::vftable;
  return param_1;
}


// FUNCTION_END

// FUNCTION_START: FUN_14002d6b4 @ 14002d6b4