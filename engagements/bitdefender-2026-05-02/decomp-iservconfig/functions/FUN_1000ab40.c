void __fastcall FUN_1000ab40(undefined4 *param_1)

{
  param_1[4] = std::exception::vftable;
  ___std_exception_destroy(param_1 + 5);
  *param_1 = std::exception::vftable;
  ___std_exception_destroy(param_1 + 1);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_1000ab70 @ 1000ab70