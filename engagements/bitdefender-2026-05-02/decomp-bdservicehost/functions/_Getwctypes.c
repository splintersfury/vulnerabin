wchar_t * __cdecl _Getwctypes(wchar_t *param_1,wchar_t *param_2,short *param_3,_Ctypevec *param_4)

{
  GetStringTypeW(1,param_1,(int)((longlong)param_2 - (longlong)param_1 >> 1),(LPWORD)param_3);
  return param_2;
}


// FUNCTION_END

// FUNCTION_START: _Towlower @ 14002e194