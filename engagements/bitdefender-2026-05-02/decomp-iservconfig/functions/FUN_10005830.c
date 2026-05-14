ios_base * __thiscall FUN_10005830(void *this,byte param_1)

{
  ios_base *piVar1;
  int iVar2;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_1004db00;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  piVar1 = (ios_base *)((int)this + -0x50);
  *(undefined ***)(*(int *)(*(int *)((int)this + -0x50) + 4) + -0x50 + (int)this) =
       std::
       basic_ostringstream<wchar_t,struct_std::char_traits<wchar_t>,class_std::allocator<wchar_t>_>
       ::vftable;
  *(int *)(*(int *)(*(int *)piVar1 + 4) + -0x54 + (int)this) = *(int *)(*(int *)piVar1 + 4) + -0x50;
  FUN_10004db0((undefined4 *)((int)this + -0x4c));
  *(undefined ***)(*(int *)(*(int *)((int)this + -0x50) + 4) + -0x50 + (int)this) =
       std::basic_ostream<wchar_t,struct_std::char_traits<wchar_t>_>::vftable;
  iVar2 = *(int *)(*(int *)((int)this + -0x50) + 4);
  *(int *)(iVar2 + -0x54 + (int)this) = iVar2 + -8;
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

// FUNCTION_START: FUN_100058e0 @ 100058e0