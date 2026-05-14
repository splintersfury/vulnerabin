longlong * FUN_14000d640(longlong *param_1)

{
  undefined8 *puVar1;
  _Locimp *p_Var2;
  
  *param_1 = (longlong)&DAT_14006b6a0;
  param_1[2] = (longlong)&DAT_14006b698;
  param_1[0x14] = 0;
  param_1[0x19] = 0;
  param_1[0x1a] = 0;
  param_1[0x1b] = 0;
  param_1[0x13] = (longlong)std::basic_ios<wchar_t,struct_std::char_traits<wchar_t>_>::vftable;
  *(undefined ***)((longlong)*(int *)(*param_1 + 4) + (longlong)param_1) =
       std::basic_istream<wchar_t,struct_std::char_traits<wchar_t>_>::vftable;
  *(int *)((longlong)*(int *)(*param_1 + 4) + -4 + (longlong)param_1) =
       *(int *)(*param_1 + 4) + -0x18;
  param_1[1] = 0;
  FUN_140011ce0((longlong)*(int *)(*param_1 + 4) + (longlong)param_1,param_1 + 3);
  *(undefined ***)((longlong)*(int *)(param_1[2] + 4) + 0x10 + (longlong)param_1) =
       std::basic_ostream<wchar_t,struct_std::char_traits<wchar_t>_>::vftable;
  *(int *)((longlong)*(int *)(param_1[2] + 4) + 0xc + (longlong)param_1) =
       *(int *)(param_1[2] + 4) + -0x10;
  *(undefined ***)((longlong)*(int *)(*param_1 + 4) + (longlong)param_1) =
       std::basic_iostream<wchar_t,struct_std::char_traits<wchar_t>_>::vftable;
  *(int *)((longlong)*(int *)(*param_1 + 4) + -4 + (longlong)param_1) =
       *(int *)(*param_1 + 4) + -0x20;
  *(undefined ***)((longlong)*(int *)(*param_1 + 4) + (longlong)param_1) =
       std::
       basic_stringstream<wchar_t,struct_std::char_traits<wchar_t>,class_std::allocator<wchar_t>_>::
       vftable;
  *(int *)((longlong)*(int *)(*param_1 + 4) + -4 + (longlong)param_1) =
       *(int *)(*param_1 + 4) + -0x98;
  param_1[3] = (longlong)std::basic_streambuf<wchar_t,struct_std::char_traits<wchar_t>_>::vftable;
  puVar1 = (undefined8 *)operator_new(0x10);
  *puVar1 = 0;
  puVar1[1] = 0;
  p_Var2 = std::locale::_Init(true);
  puVar1[1] = p_Var2;
  param_1[0xf] = (longlong)puVar1;
  param_1[6] = (longlong)(param_1 + 4);
  param_1[7] = (longlong)(param_1 + 5);
  param_1[10] = (longlong)(param_1 + 8);
  param_1[0xb] = (longlong)(param_1 + 9);
  param_1[0xd] = (longlong)(param_1 + 0xc);
  param_1[0xe] = (longlong)param_1 + 100;
  param_1[5] = 0;
  param_1[9] = 0;
  *(undefined4 *)((longlong)param_1 + 100) = 0;
  param_1[4] = 0;
  param_1[8] = 0;
  *(undefined4 *)(param_1 + 0xc) = 0;
  param_1[3] = (longlong)
               std::
               basic_stringbuf<wchar_t,struct_std::char_traits<wchar_t>,class_std::allocator<wchar_t>_>
               ::vftable;
  param_1[0x10] = 0;
  *(undefined4 *)(param_1 + 0x11) = 0;
  return param_1;
}


// FUNCTION_END

// FUNCTION_START: FUN_14000d890 @ 14000d890