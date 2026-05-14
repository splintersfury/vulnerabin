undefined8 * FUN_140011e10(undefined8 *param_1,uint param_2)

{
  *param_1 = std::numpunct<wchar_t>::vftable;
  FUN_140035ac0((LPVOID)param_1[2]);
  FUN_140035ac0((LPVOID)param_1[4]);
  FUN_140035ac0((LPVOID)param_1[5]);
  *param_1 = std::_Facet_base::vftable;
  if ((param_2 & 1) != 0) {
    FUN_14002f180();
  }
  return param_1;
}


// FUNCTION_END

// FUNCTION_START: FUN_140011e70 @ 140011e70