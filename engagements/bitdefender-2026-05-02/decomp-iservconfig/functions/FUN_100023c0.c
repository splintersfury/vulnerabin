undefined4 * __thiscall FUN_100023c0(void *this,int param_1)

{
  undefined4 uVar1;
  
  *(undefined ***)this = std::exception::vftable;
  *(undefined8 *)((int)this + 4) = 0;
  ___std_exception_copy((undefined4 *)(param_1 + 4),(undefined4 *)((int)this + 4));
  *(undefined ***)this = std::_System_error::vftable;
  uVar1 = *(undefined4 *)(param_1 + 0x10);
  *(undefined4 *)((int)this + 0xc) = *(undefined4 *)(param_1 + 0xc);
  *(undefined4 *)((int)this + 0x10) = uVar1;
  *(undefined ***)this = std::system_error::vftable;
  return (undefined4 *)this;
}


// FUNCTION_END

// FUNCTION_START: FUN_10002410 @ 10002410