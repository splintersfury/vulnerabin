undefined4 * __fastcall FUN_10001ec0(undefined4 *param_1)

{
  *(undefined8 *)(param_1 + 1) = 0;
  param_1[1] = "bad array new length";
  *param_1 = std::bad_array_new_length::vftable;
  return param_1;
}


// FUNCTION_END

// FUNCTION_START: FUN_10001f00 @ 10001f00