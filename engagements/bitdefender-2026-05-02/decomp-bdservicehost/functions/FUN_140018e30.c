void FUN_140018e30(undefined8 *param_1)

{
  param_1[4] = std::exception::vftable;
  __std_exception_destroy(param_1 + 5);
  *param_1 = std::exception::vftable;
  __std_exception_destroy(param_1 + 1);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_140018e70 @ 140018e70