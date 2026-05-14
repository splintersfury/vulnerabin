void __thiscall FUN_100029a0(void *this,char param_1)

{
  mbstate_t local_18 [2];
  wchar_t local_10 [2];
  char local_c [4];
  uint local_8;
  
  local_8 = DAT_10069054 ^ (uint)&stack0xfffffffc;
  local_c[0] = param_1;
  local_18[0] = 0;
  local_18[1] = 0;
  __Mbrtowc(local_10,local_c,1,local_18,(_Cvtvec *)((int)this + 0x18));
  FUN_1002e315(local_8 ^ (uint)&stack0xfffffffc);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_10002a00 @ 10002a00