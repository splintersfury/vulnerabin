void __fastcall FUN_10003450(int param_1)

{
  ios_base *piVar1;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_1004db00;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  piVar1 = (ios_base *)(param_1 + 0x60);
  FUN_10003240((int)piVar1);
  local_8 = 0;
  *(undefined ***)piVar1 = std::ios_base::vftable;
  std::ios_base::_Ios_base_dtor(piVar1);
  ExceptionList = local_10;
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_100034b0 @ 100034b0