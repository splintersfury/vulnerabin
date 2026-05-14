undefined4 * __thiscall FUN_1000fc00(void *this,int param_1)

{
  *(undefined ***)this = std::exception::vftable;
  *(undefined8 *)((int)this + 4) = 0;
  ___std_exception_copy((undefined4 *)(param_1 + 4),(undefined4 *)((int)this + 4));
  *(undefined ***)this = nlohmann::detail::exception::vftable;
  *(undefined4 *)((int)this + 0xc) = *(undefined4 *)(param_1 + 0xc);
  *(undefined ***)((int)this + 0x10) = std::exception::vftable;
  *(undefined8 *)((int)this + 0x14) = 0;
  ___std_exception_copy((undefined4 *)(param_1 + 0x14),(undefined4 *)((int)this + 0x14));
  *(undefined ***)((int)this + 0x10) = std::runtime_error::vftable;
  *(undefined ***)this = nlohmann::detail::other_error::vftable;
  return (undefined4 *)this;
}


// FUNCTION_END

// FUNCTION_START: FUN_1000fc70 @ 1000fc70