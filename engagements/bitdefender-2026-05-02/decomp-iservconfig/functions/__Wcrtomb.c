int __cdecl __Wcrtomb(char *param_1,wchar_t param_2,mbstate_t *param_3,_Cvtvec *param_4)

{
  int iVar1;
  int *piVar2;
  int in_ECX;
  BOOL local_8;
  
  if (param_4->_Isclocale == 0) {
    local_8 = 0;
    iVar1 = WideCharToMultiByte(param_4->_Page,0,&param_2,1,param_1,param_4->_Mbcurmax,(LPCSTR)0x0,
                                &local_8);
    if ((iVar1 != 0) && (local_8 == 0)) {
      return iVar1;
    }
  }
  else {
    local_8 = in_ECX;
    if ((ushort)param_2 < 0x100) {
      *param_1 = (char)param_2;
      return 1;
    }
  }
  piVar2 = __errno();
  *piVar2 = 0x2a;
  return -1;
}


// FUNCTION_END

// FUNCTION_START: __Mbrtowc @ 1002cf5e

/* Library Function - Single Match
    __Mbrtowc
   
   Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release */