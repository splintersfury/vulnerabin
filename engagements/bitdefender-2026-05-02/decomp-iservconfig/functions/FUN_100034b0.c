int * __fastcall FUN_100034b0(int *param_1,int param_2,int param_3)

{
  undefined8 *puVar1;
  _Locimp *p_Var2;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  puStack_c = &LAB_1004db4c;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  *param_1 = (int)&PTR_1005e1c4;
  param_1[0x1a] = 0;
  param_1[0x22] = 0;
  param_1[0x23] = 0;
  param_1[0x24] = 0;
  param_1[0x18] = (int)std::basic_ios<wchar_t,struct_std::char_traits<wchar_t>_>::vftable;
  local_8 = 0;
  *(undefined ***)((int)param_1 + *(int *)(*param_1 + 4)) =
       std::basic_ostream<wchar_t,struct_std::char_traits<wchar_t>_>::vftable;
  *(int *)(*(int *)(*param_1 + 4) + -4 + (int)param_1) = *(int *)(*param_1 + 4) + -8;
  FUN_10005ca0((void *)(*(int *)(*param_1 + 4) + (int)param_1),param_1 + 1);
  local_8 = 3;
  *(undefined ***)((int)param_1 + *(int *)(*param_1 + 4)) =
       std::
       basic_ostringstream<wchar_t,struct_std::char_traits<wchar_t>,class_std::allocator<wchar_t>_>
       ::vftable;
  *(int *)(*(int *)(*param_1 + 4) + -4 + (int)param_1) = *(int *)(*param_1 + 4) + -0x50;
  param_1[1] = (int)std::basic_streambuf<wchar_t,struct_std::char_traits<wchar_t>_>::vftable;
  puVar1 = (undefined8 *)operator_new(8);
  *puVar1 = 0;
  local_8 = CONCAT31(local_8._1_3_,4);
  p_Var2 = std::locale::_Init(true);
  *(_Locimp **)((int)puVar1 + 4) = p_Var2;
  param_1[0xe] = (int)puVar1;
  param_1[4] = (int)(param_1 + 2);
  param_1[9] = (int)(param_1 + 7);
  param_1[0xc] = (int)(param_1 + 10);
  param_1[5] = (int)(param_1 + 3);
  param_1[8] = (int)(param_1 + 6);
  param_1[0xd] = (int)(param_1 + 0xb);
  param_1[3] = 0;
  param_1[7] = 0;
  param_1[0xb] = 0;
  param_1[2] = 0;
  param_1[6] = 0;
  param_1[10] = 0;
  param_1[1] = (int)std::
                    basic_stringbuf<wchar_t,struct_std::char_traits<wchar_t>,class_std::allocator<wchar_t>_>
                    ::vftable;
  param_1[0xf] = 0;
  param_1[0x10] = 4;
  *(undefined ***)((int)param_1 + *(int *)(*param_1 + 4)) = logger_stream::vftable;
  *(int *)(*(int *)(*param_1 + 4) + -4 + (int)param_1) = *(int *)(*param_1 + 4) + -0x60;
  *(undefined1 *)(param_1 + 0x12) = 1;
  param_1[0x13] = param_2;
  param_1[0x14] = param_3;
  ExceptionList = local_10;
  return param_1;
}


// FUNCTION_END

// FUNCTION_START: FUN_10003650 @ 10003650