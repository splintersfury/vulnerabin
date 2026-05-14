undefined2 *
FUN_140002840(longlong *param_1,undefined2 param_2,undefined2 *param_3,undefined2 *param_4)

{
  char cVar1;
  
  if (param_3 != param_4) {
    do {
      cVar1 = (*(code *)PTR__guard_dispatch_icall_14005b538)(param_1,param_2,*param_3);
      if (cVar1 == '\0') {
        return param_3;
      }
      param_3 = param_3 + 1;
    } while (param_3 != param_4);
  }
  return param_3;
}


// FUNCTION_END

// FUNCTION_START: do_tolower @ 1400028a0

/* Library Function - Multiple Matches With Same Base Name
    protected: virtual unsigned short __cdecl std::ctype<unsigned short>::do_tolower(unsigned
   short)const __ptr64
    protected: virtual wchar_t __cdecl std::ctype<wchar_t>::do_tolower(wchar_t)const __ptr64
   
   Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release */