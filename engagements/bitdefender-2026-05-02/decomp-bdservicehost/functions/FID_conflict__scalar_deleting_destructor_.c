ios_base * FID_conflict__scalar_deleting_destructor_(ios_base *param_1,uint param_2)

{
  ios_base *piVar1;
  
  piVar1 = param_1 + -0x18;
  *(undefined ***)(param_1 + (longlong)*(int *)(*(longlong *)piVar1 + 4) + -0x18) =
       std::basic_istream<char,struct_std::char_traits<char>_>::vftable;
  *(int *)(param_1 + (longlong)*(int *)(*(longlong *)piVar1 + 4) + -0x1c) =
       *(int *)(*(longlong *)piVar1 + 4) + -0x18;
  *(undefined ***)param_1 = std::ios_base::vftable;
  std::ios_base::_Ios_base_dtor(param_1);
  if ((param_2 & 1) != 0) {
    FUN_14002f180();
  }
  return piVar1;
}


// FUNCTION_END

// FUNCTION_START: FUN_14001d5f0 @ 14001d5f0