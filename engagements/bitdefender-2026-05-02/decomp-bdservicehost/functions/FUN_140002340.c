undefined8 * FUN_140002340(undefined8 *param_1,longlong param_2)

{
  *param_1 = std::exception::vftable;
  param_1[1] = 0;
  param_1[2] = 0;
  __std_exception_copy((longlong *)(param_2 + 8),param_1 + 1);
  *param_1 = std::bad_cast::vftable;
  return param_1;
}


// FUNCTION_END

// FUNCTION_START: FUN_140002380 @ 140002380