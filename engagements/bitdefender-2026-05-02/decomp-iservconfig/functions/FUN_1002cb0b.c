undefined4 FUN_1002cb0b(void)

{
  return DAT_1006a8ec;
}


// FUNCTION_END

// FUNCTION_START: _Init @ 1002cb11

/* WARNING: Function: __EH_prolog3 replaced with injection: EH_prolog3 */
/* WARNING: Function: __EH_epilog3 replaced with injection: EH_epilog3 */
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */
/* Library Function - Single Match
    private: static class std::locale::_Locimp * __cdecl std::locale::_Init(bool)
   
   Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release */

_Locimp * __cdecl std::locale::_Init(bool param_1)

{
  code *pcVar1;
  _Locimp *p_Var2;
  _Lockit local_14 [12];
  undefined4 local_8;
  undefined4 uStack_4;
  
  uStack_4 = 4;
  local_8 = 0x1002cb1d;
  _Lockit::_Lockit(local_14,0);
  local_8 = 0;
  p_Var2 = DAT_1006a8ec;
  if (DAT_1006a8ec == (_Locimp *)0x0) {
    p_Var2 = _Locimp::_New_Locimp(false);
    _Setgloballocale(p_Var2);
    *(undefined4 *)(p_Var2 + 0x10) = 0x3f;
    _Yarn<char>::operator=((_Yarn<char> *)(p_Var2 + 0x18),"C");
    pcVar1 = *(code **)(*(int *)p_Var2 + 4);
    DAT_1006a8c4 = p_Var2;
    (*(code *)PTR_guard_check_icall_10052220)();
    (*pcVar1)();
    _DAT_1006a8e0 = DAT_1006a8c4;
  }
  if (param_1) {
    pcVar1 = *(code **)(*(int *)p_Var2 + 4);
    (*(code *)PTR_guard_check_icall_10052220)();
    (*pcVar1)();
  }
  FUN_1002c986((int *)local_14);
  return p_Var2;
}


// FUNCTION_END

// FUNCTION_START: _Locimp_dtor @ 1002cba1

/* Library Function - Single Match
    private: static void __cdecl std::locale::_Locimp::_Locimp_dtor(class std::locale::_Locimp *)
   
   Library: Visual Studio 2019 Release */

void __cdecl std::locale::_Locimp::_Locimp_dtor(_Locimp *param_1)

{
  code *pcVar1;
  int iVar2;
  _Lockit local_c [4];
  int *local_8;
  
  _Lockit::_Lockit(local_c,0);
  iVar2 = *(int *)(param_1 + 0xc);
  while (iVar2 != 0) {
    iVar2 = iVar2 + -1;
    local_8 = *(int **)(*(int *)(param_1 + 8) + iVar2 * 4);
    if (local_8 != (int *)0x0) {
      pcVar1 = *(code **)(*local_8 + 8);
      (*(code *)PTR_guard_check_icall_10052220)();
      local_8 = (int *)(*pcVar1)();
      if (local_8 != (int *)0x0) {
        pcVar1 = *(code **)*local_8;
        (*(code *)PTR_guard_check_icall_10052220)(1);
        (*pcVar1)();
      }
    }
  }
  FUN_100330ca(*(void **)(param_1 + 8));
  FUN_1002c986((int *)local_c);
  return;
}


// FUNCTION_END

// FUNCTION_START: _Locinfo_ctor @ 1002cc11

/* Library Function - Single Match
    public: static void __cdecl std::_Locinfo::_Locinfo_ctor(class std::_Locinfo *,char const *)
   
   Library: Visual Studio 2019 Release */

void __cdecl std::_Locinfo::_Locinfo_ctor(_Locinfo *param_1,char *param_2)

{
  char *pcVar1;
  
  pcVar1 = _setlocale(0,(char *)0x0);
  if (pcVar1 == (char *)0x0) {
    pcVar1 = "";
  }
  _Yarn<char>::operator=((_Yarn<char> *)(param_1 + 0x24),pcVar1);
  if (param_2 != (char *)0x0) {
    pcVar1 = _setlocale(0,param_2);
    if (pcVar1 != (char *)0x0) goto LAB_1002cc50;
  }
  pcVar1 = "*";
LAB_1002cc50:
  _Yarn<char>::operator=((_Yarn<char> *)(param_1 + 0x2c),pcVar1);
  return;
}


// FUNCTION_END

// FUNCTION_START: _Locinfo_dtor @ 1002cc5c

/* Library Function - Single Match
    public: static void __cdecl std::_Locinfo::_Locinfo_dtor(class std::_Locinfo *)
   
   Library: Visual Studio 2019 Release */

void __cdecl std::_Locinfo::_Locinfo_dtor(_Locinfo *param_1)

{
  if (*(int *)(param_1 + 0x24) != 0) {
    _setlocale(0,*(char **)(param_1 + 0x24));
  }
  return;
}


// FUNCTION_END

// FUNCTION_START: _New_Locimp @ 1002cc76

/* Library Function - Single Match
    private: static class std::locale::_Locimp * __cdecl std::locale::_Locimp::_New_Locimp(bool)
   
   Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release */

_Locimp * __cdecl std::locale::_Locimp::_New_Locimp(bool param_1)

{
  _Locimp *p_Var1;
  
  p_Var1 = (_Locimp *)operator_new(0x20);
  if (p_Var1 != (_Locimp *)0x0) {
    p_Var1 = (_Locimp *)_Locimp(p_Var1,param_1);
    return p_Var1;
  }
  return (_Locimp *)0x0;
}


// FUNCTION_END

// FUNCTION_START: _Setgloballocale @ 1002cc99

/* Library Function - Single Match
    private: static void __cdecl std::locale::_Setgloballocale(void *)
   
   Library: Visual Studio 2019 Release */

void __cdecl std::locale::_Setgloballocale(void *param_1)

{
  if (DAT_1006a8f0 == '\0') {
    DAT_1006a8f0 = '\x01';
    _Atexit(tidy_global);
  }
  DAT_1006a8ec = param_1;
  return;
}


// FUNCTION_END

// FUNCTION_START: __Deletegloballocale @ 1002ccc1

/* Library Function - Single Match
    __Deletegloballocale
   
   Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release */