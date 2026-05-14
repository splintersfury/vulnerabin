wchar_t * __cdecl __Getwctypes(wchar_t *param_1,wchar_t *param_2,short *param_3,_Ctypevec *param_4)

{
  GetStringTypeW(1,param_1,(int)param_2 - (int)param_1 >> 1,(LPWORD)param_3);
  return param_2;
}


// FUNCTION_END

// FUNCTION_START: __Towlower @ 1002d126