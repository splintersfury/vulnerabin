void __thiscall FUN_10009cc0(void *this,undefined4 param_1)

{
  undefined4 local_10;
  undefined1 local_c;
  uint local_8;
  
  local_8 = DAT_10069054 ^ (uint)&stack0xfffffffc;
  local_10 = param_1;
  local_c = 1;
  *(undefined ***)this = std::exception::vftable;
  *(undefined8 *)((int)this + 4) = 0;
  ___std_exception_copy(&local_10,(undefined4 *)((int)this + 4));
  *(undefined ***)this = std::runtime_error::vftable;
  FUN_1002e315(local_8 ^ (uint)&stack0xfffffffc);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_10009d20 @ 10009d20