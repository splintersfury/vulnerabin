void __fastcall FUN_1000fb00(int *param_1)

{
  ios_base *piVar1;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_1004da80;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  piVar1 = (ios_base *)(param_1 + 0x1c);
  *(undefined ***)(piVar1 + *(int *)(*param_1 + 4) + -0x70) =
       std::basic_ifstream<char,struct_std::char_traits<char>_>::vftable;
  *(int *)(piVar1 + *(int *)(*param_1 + 4) + -0x74) = *(int *)(*param_1 + 4) + -0x70;
  FUN_10010880(param_1 + 4);
  *(undefined ***)(piVar1 + *(int *)(*param_1 + 4) + -0x70) =
       std::basic_istream<char,struct_std::char_traits<char>_>::vftable;
  *(int *)(piVar1 + *(int *)(*param_1 + 4) + -0x74) = *(int *)(*param_1 + 4) + -0x18;
  local_8 = 0;
  *(undefined ***)piVar1 = std::ios_base::vftable;
  std::ios_base::_Ios_base_dtor(piVar1);
  ExceptionList = local_10;
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_1000fb90 @ 1000fb90