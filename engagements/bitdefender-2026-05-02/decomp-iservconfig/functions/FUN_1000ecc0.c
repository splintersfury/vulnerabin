ios_base * __thiscall FUN_1000ecc0(void *this,byte param_1)

{
  ios_base *piVar1;
  int iVar2;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  puStack_c = &LAB_1004db00;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  piVar1 = (ios_base *)((int)this + -0x20);
  *(undefined ***)(*(int *)(*(int *)((int)this + -0x20) + 4) + -0x20 + (int)this) =
       std::basic_iostream<wchar_t,struct_std::char_traits<wchar_t>_>::vftable;
  *(int *)(*(int *)(*(int *)piVar1 + 4) + -0x24 + (int)this) = *(int *)(*(int *)piVar1 + 4) + -0x20;
  *(undefined ***)(*(int *)(*(int *)((int)this + -0x10) + 4) + -0x10 + (int)this) =
       std::basic_ostream<wchar_t,struct_std::char_traits<wchar_t>_>::vftable;
  iVar2 = *(int *)(*(int *)((int)this + -0x10) + 4);
  *(int *)(iVar2 + -0x14 + (int)this) = iVar2 + -8;
  *(undefined ***)(*(int *)(*(int *)((int)this + -0x20) + 4) + -0x20 + (int)this) =
       std::basic_istream<wchar_t,struct_std::char_traits<wchar_t>_>::vftable;
  iVar2 = *(int *)(*(int *)((int)this + -0x20) + 4);
  *(int *)(iVar2 + -0x24 + (int)this) = iVar2 + -0x18;
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

// FUNCTION_START: FUN_1000ed80 @ 1000ed80