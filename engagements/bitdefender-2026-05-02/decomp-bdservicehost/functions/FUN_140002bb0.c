undefined8 * FUN_140002bb0(undefined8 *param_1,uint param_2)

{
  *param_1 = std::ctype<wchar_t>::vftable;
  if (*(int *)(param_1 + 4) != 0) {
    FUN_140035ac0((LPVOID)param_1[3]);
  }
  FUN_140035ac0((LPVOID)param_1[5]);
  *param_1 = std::_Facet_base::vftable;
  if ((param_2 & 1) != 0) {
    FUN_14002f180();
  }
  return param_1;
}


// FUNCTION_END

// FUNCTION_START: FUN_140002c10 @ 140002c10