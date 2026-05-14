undefined8 * FUN_1400015d0(undefined8 *param_1,uint param_2)

{
  *param_1 = std::exception::vftable;
  __std_exception_destroy(param_1 + 1);
  if ((param_2 & 1) != 0) {
    FUN_14002f180();
  }
  return param_1;
}


// FUNCTION_END

// FUNCTION_START: FUN_140001640 @ 140001640