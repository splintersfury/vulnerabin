longlong FUN_140019930(undefined8 param_1,undefined8 *param_2,longlong param_3,undefined8 param_4,
                      undefined8 *param_5)

{
  FUN_1400316b0(param_5,param_2,param_3 - (longlong)param_2);
  return param_3;
}


// FUNCTION_END

// FUNCTION_START: `scalar_deleting_destructor' @ 140019950

/* Library Function - Single Match
    protected: virtual void * __ptr64 __cdecl std::ctype<char>::`scalar deleting
   destructor'(unsigned int) __ptr64
   
   Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release */

void * __thiscall std::ctype<char>::_scalar_deleting_destructor_(ctype<char> *this,uint param_1)

{
  *(undefined ***)this = vftable;
  if (*(int *)(this + 0x20) < 1) {
    if (*(int *)(this + 0x20) < 0) {
      FUN_14002f180();
    }
  }
  else {
    FUN_140035ac0(*(LPVOID *)(this + 0x18));
  }
  FUN_140035ac0(*(LPVOID *)(this + 0x28));
  *(undefined ***)this = _Facet_base::vftable;
  if ((param_1 & 1) != 0) {
    FUN_14002f180();
  }
  return this;
}


// FUNCTION_END

// FUNCTION_START: FUN_1400199c0 @ 1400199c0