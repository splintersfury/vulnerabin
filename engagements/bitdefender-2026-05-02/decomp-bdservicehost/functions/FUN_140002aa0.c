void FUN_140002aa0(longlong param_1,wchar_t param_2)

{
  undefined1 auStack_48 [32];
  mbstate_t local_28 [2];
  char local_20 [8];
  ulonglong local_18;
  
  local_18 = DAT_14007a060 ^ (ulonglong)auStack_48;
  local_28[0] = 0;
  local_28[1] = 0;
  _Wcrtomb(local_20,param_2,local_28,(_Cvtvec *)(param_1 + 0x30));
  FUN_14002f160(local_18 ^ (ulonglong)auStack_48);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_140002b00 @ 140002b00