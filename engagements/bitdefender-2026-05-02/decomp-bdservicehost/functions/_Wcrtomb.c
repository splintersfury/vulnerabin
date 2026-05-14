int __cdecl _Wcrtomb(char *param_1,wchar_t param_2,mbstate_t *param_3,_Cvtvec *param_4)

{
  int iVar1;
  ulong *puVar2;
  wchar_t local_18 [4];
  BOOL local_10 [4];
  
  local_18[0] = param_2;
  if (param_4->_Isclocale == 0) {
    local_10[0] = 0;
    iVar1 = WideCharToMultiByte(param_4->_Page,0,local_18,1,param_1,param_4->_Mbcurmax,(LPCSTR)0x0,
                                local_10);
    if ((iVar1 != 0) && (local_10[0] == 0)) {
      return iVar1;
    }
  }
  else if ((ushort)param_2 < 0x100) {
    *param_1 = (char)param_2;
    return 1;
  }
  puVar2 = __doserrno();
  *puVar2 = 0x2a;
  return -1;
}


// FUNCTION_END

// FUNCTION_START: _Mbrtowc @ 14002df98

/* Library Function - Single Match
    _Mbrtowc
   
   Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release */