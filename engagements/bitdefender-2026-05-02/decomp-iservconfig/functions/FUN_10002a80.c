void __thiscall FUN_10002a80(void *this,wchar_t param_1)

{
  mbstate_t local_18 [2];
  char local_10 [8];
  uint local_8;
  
  local_8 = DAT_10069054 ^ (uint)&stack0xfffffffc;
  local_18[0] = 0;
  local_18[1] = 0;
  __Wcrtomb(local_10,param_1,local_18,(_Cvtvec *)((int)this + 0x18));
  FUN_1002e315(local_8 ^ (uint)&stack0xfffffffc);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_10002ad0 @ 10002ad0