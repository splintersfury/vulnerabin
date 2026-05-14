void __fastcall FUN_1002c986(int *param_1)

{
  int iVar1;
  
  iVar1 = *param_1;
  if (iVar1 != 0) {
    if (iVar1 < 8) {
      FUN_1002dbdb((LPCRITICAL_SECTION)(&DAT_1006a800 + iVar1 * 0x18));
    }
    return;
  }
  ___acrt_unlock(4);
  return;
}


// FUNCTION_END

// FUNCTION_START: _Locimp @ 1002c9a5

/* Library Function - Single Match
    private: __thiscall std::locale::_Locimp::_Locimp(bool)
   
   Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release */

_Locimp * __thiscall std::locale::_Locimp::_Locimp(_Locimp *this,bool param_1)

{
  *(undefined4 *)(this + 4) = 1;
  *(undefined ***)this = vftable;
  *(undefined4 *)(this + 8) = 0;
  *(undefined4 *)(this + 0xc) = 0;
  *(undefined4 *)(this + 0x10) = 0;
  this[0x14] = (_Locimp)param_1;
  *(undefined4 *)(this + 0x18) = 0;
  this[0x1c] = (_Locimp)0x0;
  _Yarn<char>::operator=((_Yarn<char> *)(this + 0x18),"*");
  return this;
}


// FUNCTION_END

// FUNCTION_START: FUN_1002c9e6 @ 1002c9e6