undefined4 * __thiscall FUN_10001f00(void *this,byte param_1)

{
  *(undefined ***)this = std::exception::vftable;
  ___std_exception_destroy((undefined4 *)((int)this + 4));
  if ((param_1 & 1) != 0) {
    FUN_1002e346(this);
  }
  return (undefined4 *)this;
}


// FUNCTION_END

// FUNCTION_START: FUN_10001f30 @ 10001f30