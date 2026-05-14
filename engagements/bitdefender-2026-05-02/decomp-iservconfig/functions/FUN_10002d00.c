undefined4 * __thiscall FUN_10002d00(void *this,int param_1)

{
  undefined4 uVar1;
  
  *(undefined ***)this = std::exception::vftable;
  *(undefined8 *)((int)this + 4) = 0;
  ___std_exception_copy((undefined4 *)(param_1 + 4),(undefined4 *)((int)this + 4));
  *(undefined ***)this = std::_System_error::vftable;
  uVar1 = *(undefined4 *)(param_1 + 0x10);
  *(undefined4 *)((int)this + 0xc) = *(undefined4 *)(param_1 + 0xc);
  *(undefined4 *)((int)this + 0x10) = uVar1;
  *(undefined ***)this = std::ios_base::failure::vftable;
  return (undefined4 *)this;
}


// FUNCTION_END

// FUNCTION_START: FUN_10002d50 @ 10002d50