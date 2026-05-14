undefined4 * __thiscall FUN_10002010(void *this,int param_1)

{
  *(undefined ***)this = std::exception::vftable;
  *(undefined8 *)((int)this + 4) = 0;
  ___std_exception_copy((undefined4 *)(param_1 + 4),(undefined4 *)((int)this + 4));
  *(undefined ***)this = std::runtime_error::vftable;
  return (undefined4 *)this;
}


// FUNCTION_END

// FUNCTION_START: FUN_10002050 @ 10002050