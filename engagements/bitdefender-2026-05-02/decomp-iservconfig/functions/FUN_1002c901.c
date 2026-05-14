undefined4 __fastcall FUN_1002c901(undefined4 param_1)

{
  LPCRITICAL_SECTION p_Var1;
  
  LOCK();
  DAT_10069000 = DAT_10069000 + 1;
  UNLOCK();
  if (DAT_10069000 == 0) {
    p_Var1 = (LPCRITICAL_SECTION)&DAT_1006a800;
    do {
      FUN_1002dbb8(p_Var1);
      p_Var1 = p_Var1 + 1;
    } while (p_Var1 != (LPCRITICAL_SECTION)&DAT_1006a8c0);
  }
  return param_1;
}


// FUNCTION_END

// FUNCTION_START: _Lockit @ 1002c92e

/* Library Function - Single Match
    public: __thiscall std::_Lockit::_Lockit(int)
   
   Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release */

_Lockit * __thiscall std::_Lockit::_Lockit(_Lockit *this,int param_1)

{
  *(int *)this = param_1;
  if (param_1 == 0) {
    __lock_locales();
  }
  else if (param_1 < 8) {
    __Mtxlock((_Rmtx *)(&DAT_1006a800 + param_1 * 0x18));
  }
  return this;
}


// FUNCTION_END

// FUNCTION_START: FUN_1002c95f @ 1002c95f