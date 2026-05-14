void __fastcall FUN_1000dfd0(int *param_1)

{
  undefined8 *puVar1;
  _Locimp *p_Var2;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  puStack_c = &LAB_1004e8b7;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  *param_1 = (int)&DAT_1005e79c;
  param_1[4] = (int)&PTR_1005e794;
  param_1[0x1c] = 0;
  param_1[0x24] = 0;
  param_1[0x25] = 0;
  param_1[0x26] = 0;
  param_1[0x1a] = (int)std::basic_ios<wchar_t,struct_std::char_traits<wchar_t>_>::vftable;
  local_8 = 0;
  *(undefined ***)((int)param_1 + *(int *)(*param_1 + 4)) =
       std::basic_istream<wchar_t,struct_std::char_traits<wchar_t>_>::vftable;
  *(int *)(*(int *)(*param_1 + 4) + -4 + (int)param_1) = *(int *)(*param_1 + 4) + -0x18;
  param_1[2] = 0;
  param_1[3] = 0;
  FUN_10005ca0((void *)(*(int *)(*param_1 + 4) + (int)param_1),param_1 + 6);
  *(undefined ***)((int)param_1 + *(int *)(param_1[4] + 4) + 0x10) =
       std::basic_ostream<wchar_t,struct_std::char_traits<wchar_t>_>::vftable;
  *(int *)(*(int *)(param_1[4] + 4) + 0xc + (int)param_1) = *(int *)(param_1[4] + 4) + -8;
  *(undefined ***)((int)param_1 + *(int *)(*param_1 + 4)) =
       std::basic_iostream<wchar_t,struct_std::char_traits<wchar_t>_>::vftable;
  *(int *)(*(int *)(*param_1 + 4) + -4 + (int)param_1) = *(int *)(*param_1 + 4) + -0x20;
  local_8 = 5;
  *(undefined ***)((int)param_1 + *(int *)(*param_1 + 4)) =
       std::
       basic_stringstream<wchar_t,struct_std::char_traits<wchar_t>,class_std::allocator<wchar_t>_>::
       vftable;
  *(int *)(*(int *)(*param_1 + 4) + -4 + (int)param_1) = *(int *)(*param_1 + 4) + -0x68;
  param_1[6] = (int)std::basic_streambuf<wchar_t,struct_std::char_traits<wchar_t>_>::vftable;
  puVar1 = (undefined8 *)operator_new(8);
  *puVar1 = 0;
  local_8 = CONCAT31(local_8._1_3_,6);
  p_Var2 = std::locale::_Init(true);
  *(_Locimp **)((int)puVar1 + 4) = p_Var2;
  param_1[0x13] = (int)puVar1;
  param_1[9] = (int)(param_1 + 7);
  param_1[10] = (int)(param_1 + 8);
  param_1[0xd] = (int)(param_1 + 0xb);
  param_1[0xe] = (int)(param_1 + 0xc);
  param_1[0x11] = (int)(param_1 + 0xf);
  param_1[0x12] = (int)(param_1 + 0x10);
  param_1[8] = 0;
  param_1[0xc] = 0;
  param_1[0x10] = 0;
  param_1[7] = 0;
  param_1[0xb] = 0;
  param_1[0xf] = 0;
  param_1[6] = (int)std::
                    basic_stringbuf<wchar_t,struct_std::char_traits<wchar_t>,class_std::allocator<wchar_t>_>
                    ::vftable;
  param_1[0x14] = 0;
  param_1[0x15] = 0;
  ExceptionList = local_10;
  return;
}


// FUNCTION_END

// FUNCTION_START: ~basic_iostream<char,struct_std::char_traits<char>_> @ 1000e190

/* Library Function - Single Match
    public: virtual __thiscall std::basic_iostream<char,struct std::char_traits<char>
   >::~basic_iostream<char,struct std::char_traits<char> >(void)
   
   Library: Visual Studio 2019 Release */

void __thiscall
std::basic_iostream<char,struct_std::char_traits<char>_>::
~basic_iostream<char,struct_std::char_traits<char>_>
          (basic_iostream<char,struct_std::char_traits<char>_> *this)

{
  *(undefined ***)(this + *(int *)(*(int *)(this + -0x20) + 4) + -0x20) =
       basic_iostream<wchar_t,struct_std::char_traits<wchar_t>_>::vftable;
  *(int *)(this + *(int *)(*(int *)(this + -0x20) + 4) + -0x24) =
       *(int *)(*(int *)(this + -0x20) + 4) + -0x20;
  *(undefined ***)(this + *(int *)(*(int *)(this + -0x10) + 4) + -0x10) =
       basic_ostream<wchar_t,struct_std::char_traits<wchar_t>_>::vftable;
  *(int *)(this + *(int *)(*(int *)(this + -0x10) + 4) + -0x14) =
       *(int *)(*(int *)(this + -0x10) + 4) + -8;
  *(undefined ***)(this + *(int *)(*(int *)(this + -0x20) + 4) + -0x20) =
       basic_istream<wchar_t,struct_std::char_traits<wchar_t>_>::vftable;
  *(int *)(this + *(int *)(*(int *)(this + -0x20) + 4) + -0x24) =
       *(int *)(*(int *)(this + -0x20) + 4) + -0x18;
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_1000e1f0 @ 1000e1f0