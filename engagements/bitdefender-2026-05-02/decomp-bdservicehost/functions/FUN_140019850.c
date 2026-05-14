byte * FUN_140019850(longlong param_1,byte *param_2,byte *param_3)

{
  int iVar1;
  
  if (param_2 != param_3) {
    do {
      iVar1 = _Tolower((uint)*param_2,(_Ctypevec *)(param_1 + 0x10));
      *param_2 = (byte)iVar1;
      param_2 = param_2 + 1;
    } while (param_2 != param_3);
  }
  return param_2;
}


// FUNCTION_END

// FUNCTION_START: do_toupper @ 1400198a0

/* Library Function - Single Match
    protected: virtual char __cdecl std::ctype<char>::do_toupper(char)const __ptr64
   
   Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release */

char __thiscall std::ctype<char>::do_toupper(ctype<char> *this,char param_1)

{
  int iVar1;
  
  iVar1 = _Toupper((uint)(byte)param_1,(_Ctypevec *)(this + 0x10));
  return (char)iVar1;
}


// FUNCTION_END

// FUNCTION_START: FUN_1400198b0 @ 1400198b0