undefined8 * FUN_14002d3d0(undefined8 *param_1,undefined8 *param_2)

{
  undefined8 uVar1;
  
  uVar1 = param_2[1];
  *param_1 = *param_2;
  param_1[1] = uVar1;
  param_1[2] = 0;
  param_1[4] = 0;
  param_1[5] = 0;
  uVar1 = param_2[3];
  param_1[2] = param_2[2];
  param_1[3] = uVar1;
  uVar1 = param_2[5];
  param_1[4] = param_2[4];
  param_1[5] = uVar1;
  param_2[4] = 0;
  *(undefined1 *)(param_2 + 2) = 0;
  param_2[5] = 0xf;
  *(undefined1 *)(param_1 + 6) = 1;
  return param_1;
}


// FUNCTION_END

// FUNCTION_START: _Init_locks @ 14002d40c

/* Library Function - Single Match
    public: __cdecl std::_Init_locks::_Init_locks(void) __ptr64
   
   Library: Visual Studio 2019 Release */

_Init_locks * __thiscall std::_Init_locks::_Init_locks(_Init_locks *this)

{
  LPCRITICAL_SECTION p_Var1;
  
  LOCK();
  DAT_14007a000 = DAT_14007a000 + 1;
  UNLOCK();
  if (DAT_14007a000 == 0) {
    p_Var1 = (LPCRITICAL_SECTION)&DAT_14007bc80;
    do {
      FUN_14002ec80(p_Var1);
      p_Var1 = p_Var1 + 1;
    } while (p_Var1 != (LPCRITICAL_SECTION)&DAT_14007bdc0);
  }
  return this;
}


// FUNCTION_END

// FUNCTION_START: _Lockit @ 14002d450

/* Library Function - Single Match
    public: __cdecl std::_Lockit::_Lockit(int) __ptr64
   
   Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release */

_Lockit * __thiscall std::_Lockit::_Lockit(_Lockit *this,int param_1)

{
  *(int *)this = param_1;
  if (param_1 == 0) {
    _lock_locales();
  }
  else if (param_1 < 8) {
    EnterCriticalSection((LPCRITICAL_SECTION)(&DAT_14007bc80 + (longlong)param_1 * 0x28));
  }
  return this;
}


// FUNCTION_END

// FUNCTION_START: FUN_14002d48c @ 14002d48c