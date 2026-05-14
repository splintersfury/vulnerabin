undefined4 * __thiscall FUN_1000ab70(void *this,byte param_1)

{
  *(undefined ***)((int)this + 0x10) = std::exception::vftable;
  ___std_exception_destroy((undefined4 *)((int)this + 0x14));
  *(undefined ***)this = std::exception::vftable;
  ___std_exception_destroy((undefined4 *)((int)this + 4));
  if ((param_1 & 1) != 0) {
    FUN_1002e346(this);
  }
  return (undefined4 *)this;
}


// FUNCTION_END

// FUNCTION_START: FUN_1000abb0 @ 1000abb0