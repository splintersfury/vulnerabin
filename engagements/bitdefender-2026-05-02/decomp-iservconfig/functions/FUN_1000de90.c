void __fastcall FUN_1000de90(int *param_1)

{
  ios_base *piVar1;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_1004da80;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  piVar1 = (ios_base *)(param_1 + 0x1a);
  *(undefined ***)(piVar1 + *(int *)(*param_1 + 4) + -0x68) =
       std::
       basic_stringstream<wchar_t,struct_std::char_traits<wchar_t>,class_std::allocator<wchar_t>_>::
       vftable;
  *(int *)(piVar1 + *(int *)(*param_1 + 4) + -0x6c) = *(int *)(*param_1 + 4) + -0x68;
  FUN_10004db0(param_1 + 6);
  *(undefined ***)(piVar1 + *(int *)(*param_1 + 4) + -0x68) =
       std::basic_iostream<wchar_t,struct_std::char_traits<wchar_t>_>::vftable;
  *(int *)(piVar1 + *(int *)(*param_1 + 4) + -0x6c) = *(int *)(*param_1 + 4) + -0x20;
  *(undefined ***)(piVar1 + *(int *)(param_1[4] + 4) + -0x58) =
       std::basic_ostream<wchar_t,struct_std::char_traits<wchar_t>_>::vftable;
  *(int *)(piVar1 + *(int *)(param_1[4] + 4) + -0x5c) = *(int *)(param_1[4] + 4) + -8;
  *(undefined ***)(piVar1 + *(int *)(*param_1 + 4) + -0x68) =
       std::basic_istream<wchar_t,struct_std::char_traits<wchar_t>_>::vftable;
  *(int *)(piVar1 + *(int *)(*param_1 + 4) + -0x6c) = *(int *)(*param_1 + 4) + -0x18;
  local_8 = 0;
  *(undefined ***)piVar1 = std::ios_base::vftable;
  std::ios_base::_Ios_base_dtor(piVar1);
  ExceptionList = local_10;
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_1000df60 @ 1000df60