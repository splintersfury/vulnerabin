ios_base * __thiscall FUN_100033d0(void *this,byte param_1)

{
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_1004db00;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  FUN_10003240((int)this);
  local_8 = 0;
  *(undefined ***)this = std::ios_base::vftable;
  std::ios_base::_Ios_base_dtor((ios_base *)this);
  if ((param_1 & 1) != 0) {
    FUN_1002e346((ios_base *)((int)this + -0x60));
  }
  ExceptionList = local_10;
  return (ios_base *)((int)this + -0x60);
}


// FUNCTION_END

// FUNCTION_START: FUN_10003450 @ 10003450