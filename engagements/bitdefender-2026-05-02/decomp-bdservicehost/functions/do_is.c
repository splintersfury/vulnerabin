bool do_is(longlong param_1,ushort param_2,wchar_t param_3)

{
  ushort uVar1;
  
  uVar1 = _Getwctype(param_3,(_Ctypevec *)(param_1 + 0x10));
  return (param_2 & uVar1) != 0;
}


// FUNCTION_END

// FUNCTION_START: FUN_1400027c0 @ 1400027c0