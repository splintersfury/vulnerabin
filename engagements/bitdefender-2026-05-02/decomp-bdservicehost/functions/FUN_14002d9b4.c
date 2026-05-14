undefined8 FUN_14002d9b4(void)

{
  return DAT_14007be18;
}


// FUNCTION_END

// FUNCTION_START: _Init @ 14002d9bc

/* Library Function - Single Match
    private: static class std::locale::_Locimp * __ptr64 __cdecl std::locale::_Init(bool)
   
   Library: Visual Studio 2019 Release */

_Locimp * __cdecl std::locale::_Init(bool param_1)

{
  undefined *puVar1;
  _Locimp *p_Var2;
  undefined8 *puVar3;
  char *pcVar4;
  char *pcVar5;
  _Lockit local_res8 [8];
  
  _Lockit::_Lockit(local_res8,0);
  p_Var2 = DAT_14007be18;
  if (DAT_14007be18 == (_Locimp *)0x0) {
    p_Var2 = _Locimp::_New_Locimp(false);
    _Setgloballocale(p_Var2);
    *(undefined4 *)(p_Var2 + 0x20) = 0x3f;
    puVar1 = *(undefined **)(p_Var2 + 0x28);
    if (puVar1 != &DAT_14005cb94) {
      if (puVar1 != (undefined *)0x0) {
        FUN_140035ac0(puVar1);
      }
      *(undefined8 *)(p_Var2 + 0x28) = 0;
      pcVar4 = "C";
      do {
        pcVar5 = pcVar4;
        pcVar4 = pcVar5 + 1;
      } while (*pcVar4 != '\0');
      pcVar5 = pcVar5 + -0x14005cb92;
      puVar3 = (undefined8 *)_malloc_base((ulonglong)pcVar5);
      *(undefined8 **)(p_Var2 + 0x28) = puVar3;
      if (puVar3 != (undefined8 *)0x0) {
        FUN_1400316b0(puVar3,(undefined8 *)&DAT_14005cb94,(ulonglong)pcVar5);
      }
    }
    DAT_14007bdc8 = p_Var2;
    (*(code *)PTR__guard_dispatch_icall_14005b538)(p_Var2);
    DAT_14007bdf8 = DAT_14007bdc8;
  }
  if (param_1) {
    (*(code *)PTR__guard_dispatch_icall_14005b538)(p_Var2);
  }
  _Lockit::~_Lockit(local_res8);
  return p_Var2;
}


// FUNCTION_END

// FUNCTION_START: _Locimp_dtor @ 14002dab4

/* Library Function - Single Match
    private: static void __cdecl std::locale::_Locimp::_Locimp_dtor(class std::locale::_Locimp *
   __ptr64)
   
   Library: Visual Studio 2019 Release */

void __cdecl std::locale::_Locimp::_Locimp_dtor(_Locimp *param_1)

{
  longlong lVar1;
  longlong lVar2;
  _Lockit local_res8 [8];
  
  _Lockit::_Lockit(local_res8,0);
  lVar2 = *(longlong *)(param_1 + 0x18);
  while (lVar2 != 0) {
    lVar2 = lVar2 + -1;
    if (*(longlong *)(*(longlong *)(param_1 + 0x10) + lVar2 * 8) != 0) {
      lVar1 = (*(code *)PTR__guard_dispatch_icall_14005b538)();
      if (lVar1 != 0) {
        (*(code *)PTR__guard_dispatch_icall_14005b538)(lVar1,1);
      }
    }
  }
  FUN_140035ac0(*(LPVOID *)(param_1 + 0x10));
  _Lockit::~_Lockit(local_res8);
  return;
}


// FUNCTION_END

// FUNCTION_START: _Locinfo_ctor @ 14002db30

/* Library Function - Single Match
    public: static void __cdecl std::_Locinfo::_Locinfo_ctor(class std::_Locinfo * __ptr64,char
   const * __ptr64)
   
   Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release */

void __cdecl std::_Locinfo::_Locinfo_ctor(_Locinfo *param_1,char *param_2)

{
  char *pcVar1;
  
  pcVar1 = setlocale(0,(char *)0x0);
  if (pcVar1 == (char *)0x0) {
    pcVar1 = "";
  }
  _Yarn<char>::operator=((_Yarn<char> *)(param_1 + 0x48),pcVar1);
  if (param_2 != (char *)0x0) {
    param_2 = setlocale(0,param_2);
  }
  if (param_2 == (char *)0x0) {
    param_2 = "*";
  }
  _Yarn<char>::operator=((_Yarn<char> *)(param_1 + 0x58),param_2);
  return;
}


// FUNCTION_END

// FUNCTION_START: _Locinfo_dtor @ 14002db9c

/* Library Function - Single Match
    public: static void __cdecl std::_Locinfo::_Locinfo_dtor(class std::_Locinfo * __ptr64)
   
   Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release */

void __cdecl std::_Locinfo::_Locinfo_dtor(_Locinfo *param_1)

{
  if (*(char **)(param_1 + 0x48) != (char *)0x0) {
    setlocale(0,*(char **)(param_1 + 0x48));
  }
  return;
}


// FUNCTION_END

// FUNCTION_START: _New_Locimp @ 14002dbb8

/* Library Function - Single Match
    private: static class std::locale::_Locimp * __ptr64 __cdecl
   std::locale::_Locimp::_New_Locimp(bool)
   
   Library: Visual Studio 2019 Release */

_Locimp * __cdecl std::locale::_Locimp::_New_Locimp(bool param_1)

{
  _Locimp *this;
  _Locimp *p_Var1;
  
  this = (_Locimp *)operator_new(0x38);
  p_Var1 = (_Locimp *)0x0;
  if (this != (_Locimp *)0x0) {
    p_Var1 = (_Locimp *)_Locimp(this,param_1);
  }
  return p_Var1;
}


// FUNCTION_END

// FUNCTION_START: _Setgloballocale @ 14002dbe8

/* Library Function - Single Match
    private: static void __cdecl std::locale::_Setgloballocale(void * __ptr64)
   
   Library: Visual Studio 2019 Release */

void __cdecl std::locale::_Setgloballocale(void *param_1)

{
  if (DAT_14007be20 == '\0') {
    DAT_14007be20 = '\x01';
    _Atexit(FUN_14002dc60);
  }
  DAT_14007be18 = param_1;
  return;
}


// FUNCTION_END

// FUNCTION_START: _Deletegloballocale @ 14002dc1c

/* Library Function - Single Match
    _Deletegloballocale
   
   Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release */