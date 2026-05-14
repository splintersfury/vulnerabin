undefined8 * FUN_14001d350(undefined8 *param_1,longlong param_2)

{
  *param_1 = std::exception::vftable;
  param_1[1] = 0;
  param_1[2] = 0;
  __std_exception_copy((longlong *)(param_2 + 8),param_1 + 1);
  *param_1 = nlohmann::detail::exception::vftable;
  *(undefined4 *)(param_1 + 3) = *(undefined4 *)(param_2 + 0x18);
  param_1[4] = std::exception::vftable;
  param_1[5] = 0;
  param_1[6] = 0;
  __std_exception_copy((longlong *)(param_2 + 0x28),param_1 + 5);
  param_1[4] = std::runtime_error::vftable;
  return param_1;
}


// FUNCTION_END

// FUNCTION_START: FUN_14001d3d0 @ 14001d3d0