ios_base * __thiscall FUN_100058e0(void *this,byte param_1)

{
  ios_base *piVar1;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  puStack_c = &LAB_1004da80;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  piVar1 = (ios_base *)((int)this + -8);
  *(undefined ***)(*(int *)(*(int *)((int)this + -8) + 4) + -8 + (int)this) =
       std::basic_ostream<wchar_t,struct_std::char_traits<wchar_t>_>::vftable;
  *(int *)(*(int *)(*(int *)piVar1 + 4) + -0xc + (int)this) = *(int *)(*(int *)piVar1 + 4) + -8;
  local_8 = 0;
  *(undefined ***)this = std::ios_base::vftable;
  std::ios_base::_Ios_base_dtor((ios_base *)this);
  if ((param_1 & 1) != 0) {
    FUN_1002e346(piVar1);
  }
  ExceptionList = local_10;
  return piVar1;
}


// FUNCTION_END

// FUNCTION_START: FUN_10005960 @ 10005960