void FUN_140002960(longlong param_1,char param_2)

{
  undefined1 auStackY_58 [32];
  char local_28 [8];
  wchar_t local_20 [4];
  mbstate_t local_18 [2];
  ulonglong local_10;
  
  local_10 = DAT_14007a060 ^ (ulonglong)auStackY_58;
  local_18[0] = 0;
  local_18[1] = 0;
  local_28[0] = param_2;
  _Mbrtowc(local_20,local_28,1,local_18,(_Cvtvec *)(param_1 + 0x30));
  FUN_14002f160(local_10 ^ (ulonglong)auStackY_58);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_1400029d0 @ 1400029d0