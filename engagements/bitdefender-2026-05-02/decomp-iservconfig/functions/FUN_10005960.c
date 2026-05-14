ios_base * __thiscall FUN_10005960(void *this,byte param_1)

{
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  puStack_c = &LAB_1004da80;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  local_8 = 0;
  *(undefined ***)this = std::ios_base::vftable;
  std::ios_base::_Ios_base_dtor((ios_base *)this);
  if ((param_1 & 1) != 0) {
    FUN_1002e346(this);
  }
  ExceptionList = local_10;
  return (ios_base *)this;
}


// FUNCTION_END

// FUNCTION_START: FUN_100059d0 @ 100059d0