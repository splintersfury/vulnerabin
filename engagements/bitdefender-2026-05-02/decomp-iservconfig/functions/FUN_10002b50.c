undefined4 * __thiscall FUN_10002b50(void *this,byte param_1)

{
  *(undefined ***)this = std::ctype<wchar_t>::vftable;
  if (*(int *)((int)this + 0x10) != 0) {
    FUN_100330ca(*(void **)((int)this + 0xc));
  }
  FUN_100330ca(*(void **)((int)this + 0x14));
  *(undefined ***)this = std::_Facet_base::vftable;
  if ((param_1 & 1) != 0) {
    FUN_1002e346(this);
  }
  return (undefined4 *)this;
}


// FUNCTION_END

// FUNCTION_START: FUN_10002ba0 @ 10002ba0