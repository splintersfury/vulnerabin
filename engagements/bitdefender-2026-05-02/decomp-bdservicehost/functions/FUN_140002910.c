wchar_t * FUN_140002910(longlong param_1,wchar_t *param_2,wchar_t *param_3)

{
  wchar_t wVar1;
  
  if (param_2 != param_3) {
    do {
      wVar1 = _Towupper(*param_2,(_Ctypevec *)(param_1 + 0x10));
      *param_2 = wVar1;
      param_2 = param_2 + 1;
    } while (param_2 != param_3);
  }
  return param_2;
}


// FUNCTION_END

// FUNCTION_START: FUN_140002960 @ 140002960