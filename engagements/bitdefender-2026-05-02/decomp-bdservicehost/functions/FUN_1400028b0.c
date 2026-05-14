wchar_t * FUN_1400028b0(longlong param_1,wchar_t *param_2,wchar_t *param_3)

{
  wchar_t wVar1;
  
  if (param_2 != param_3) {
    do {
      wVar1 = _Towlower(*param_2,(_Ctypevec *)(param_1 + 0x10));
      *param_2 = wVar1;
      param_2 = param_2 + 1;
    } while (param_2 != param_3);
  }
  return param_2;
}


// FUNCTION_END

// FUNCTION_START: do_toupper @ 140002900

/* Library Function - Multiple Matches With Same Base Name
    protected: virtual unsigned short __cdecl std::ctype<unsigned short>::do_toupper(unsigned
   short)const __ptr64
    protected: virtual wchar_t __cdecl std::ctype<wchar_t>::do_toupper(wchar_t)const __ptr64
   
   Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release */