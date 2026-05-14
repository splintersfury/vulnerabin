void __fastcall FUN_10005190(ios_base *param_1)

{
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  puStack_c = &LAB_1004dd10;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  local_8 = 0;
  *(undefined ***)param_1 = std::ios_base::vftable;
  std::ios_base::_Ios_base_dtor(param_1);
  ExceptionList = local_10;
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_100051e0 @ 100051e0