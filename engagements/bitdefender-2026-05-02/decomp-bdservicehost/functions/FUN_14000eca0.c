undefined8 * FUN_14000eca0(undefined8 *param_1,longlong param_2)

{
  *param_1 = std::exception::vftable;
  param_1[1] = 0;
  param_1[2] = 0;
  __std_exception_copy((longlong *)(param_2 + 8),param_1 + 1);
  *param_1 = stdext::bad_expected_access::vftable;
  return param_1;
}


// FUNCTION_END

// FUNCTION_START: FUN_14000ece0 @ 14000ece0