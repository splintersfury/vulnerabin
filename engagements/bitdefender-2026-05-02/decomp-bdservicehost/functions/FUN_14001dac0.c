undefined8 * FUN_14001dac0(undefined8 *param_1)

{
  undefined8 *puVar1;
  _Locimp *p_Var2;
  
  *param_1 = std::basic_streambuf<char,struct_std::char_traits<char>_>::vftable;
  puVar1 = (undefined8 *)operator_new(0x10);
  *puVar1 = 0;
  puVar1[1] = 0;
  p_Var2 = std::locale::_Init(true);
  puVar1[1] = p_Var2;
  param_1[0xc] = puVar1;
  *param_1 = std::basic_filebuf<char,struct_std::char_traits<char>_>::vftable;
  *(undefined1 *)((longlong)param_1 + 0x7c) = 0;
  *(undefined1 *)((longlong)param_1 + 0x71) = 0;
  param_1[3] = param_1 + 1;
  param_1[4] = param_1 + 2;
  param_1[7] = param_1 + 5;
  param_1[8] = param_1 + 6;
  param_1[10] = param_1 + 9;
  param_1[0xb] = (undefined4 *)((longlong)param_1 + 0x4c);
  param_1[2] = 0;
  param_1[6] = 0;
  *(undefined4 *)((longlong)param_1 + 0x4c) = 0;
  param_1[1] = 0;
  param_1[5] = 0;
  *(undefined4 *)(param_1 + 9) = 0;
  param_1[0x10] = 0;
  *(undefined8 *)((longlong)param_1 + 0x74) = DAT_14007d658;
  param_1[0xd] = 0;
  return param_1;
}


// FUNCTION_END

// FUNCTION_START: FUN_14001db80 @ 14001db80