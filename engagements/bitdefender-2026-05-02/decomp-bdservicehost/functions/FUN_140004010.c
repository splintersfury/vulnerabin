void FUN_140004010(longlong *param_1)

{
  ios_base *piVar1;
  
  piVar1 = (ios_base *)(param_1 + 0x13);
  *(undefined ***)(piVar1 + (longlong)*(int *)(*param_1 + 4) + -0x98) =
       std::
       basic_stringstream<wchar_t,struct_std::char_traits<wchar_t>,class_std::allocator<wchar_t>_>::
       vftable;
  *(int *)(piVar1 + (longlong)*(int *)(*param_1 + 4) + -0x9c) = *(int *)(*param_1 + 4) + -0x98;
  FUN_14000de30(param_1 + 3);
  *(undefined ***)(piVar1 + (longlong)*(int *)(*param_1 + 4) + -0x98) =
       std::basic_iostream<wchar_t,struct_std::char_traits<wchar_t>_>::vftable;
  *(int *)(piVar1 + (longlong)*(int *)(*param_1 + 4) + -0x9c) = *(int *)(*param_1 + 4) + -0x20;
  *(undefined ***)(piVar1 + (longlong)*(int *)(param_1[2] + 4) + -0x88) =
       std::basic_ostream<wchar_t,struct_std::char_traits<wchar_t>_>::vftable;
  *(int *)(piVar1 + (longlong)*(int *)(param_1[2] + 4) + -0x8c) = *(int *)(param_1[2] + 4) + -0x10;
  *(undefined ***)(piVar1 + (longlong)*(int *)(*param_1 + 4) + -0x98) =
       std::basic_istream<wchar_t,struct_std::char_traits<wchar_t>_>::vftable;
  *(int *)(piVar1 + (longlong)*(int *)(*param_1 + 4) + -0x9c) = *(int *)(*param_1 + 4) + -0x18;
  *(undefined ***)piVar1 = std::ios_base::vftable;
  std::ios_base::_Ios_base_dtor(piVar1);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_140004110 @ 140004110