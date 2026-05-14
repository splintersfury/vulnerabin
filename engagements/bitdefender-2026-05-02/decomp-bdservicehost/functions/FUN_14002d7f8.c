int FUN_14002d7f8(int param_1)

{
  int *piVar1;
  
  piVar1 = &DAT_14005bd30;
  do {
    if (*piVar1 == param_1) {
      return piVar1[1];
    }
    piVar1 = piVar1 + 2;
  } while (piVar1 != (int *)&DAT_14005bfa8);
  return 0;
}


// FUNCTION_END

// FUNCTION_START: _Locimp @ 14002d81c

/* Library Function - Single Match
    private: __cdecl std::locale::_Locimp::_Locimp(bool) __ptr64
   
   Library: Visual Studio 2019 Release */

_Locimp * __thiscall std::locale::_Locimp::_Locimp(_Locimp *this,bool param_1)

{
  char *pcVar1;
  undefined8 *puVar2;
  char *pcVar3;
  
  *(undefined8 *)(this + 0x10) = 0;
  *(undefined8 *)(this + 0x18) = 0;
  *(undefined4 *)(this + 0x20) = 0;
  *(undefined ***)this = vftable;
  *(undefined4 *)(this + 8) = 1;
  this[0x24] = (_Locimp)param_1;
  *(undefined8 *)(this + 0x28) = 0;
  this[0x30] = (_Locimp)0x0;
  pcVar1 = "*";
  do {
    pcVar3 = pcVar1;
    pcVar1 = pcVar3 + 1;
  } while (pcVar3[1] != '\0');
  puVar2 = (undefined8 *)_malloc_base((ulonglong)(pcVar3 + -0x14005cb8e));
  *(undefined8 **)(this + 0x28) = puVar2;
  if (puVar2 != (undefined8 *)0x0) {
    FUN_1400316b0(puVar2,(undefined8 *)&DAT_14005cb90,(ulonglong)(pcVar3 + -0x14005cb8e));
  }
  return this;
}


// FUNCTION_END

// FUNCTION_START: operator= @ 14002d8a4

/* Library Function - Single Match
    public: class std::_Yarn<char> & __ptr64 __cdecl std::_Yarn<char>::operator=(char const *
   __ptr64) __ptr64
   
   Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release */

_Yarn<char> * __thiscall std::_Yarn<char>::operator=(_Yarn<char> *this,char *param_1)

{
  char cVar1;
  undefined8 *puVar2;
  char *pcVar3;
  
  pcVar3 = *(char **)this;
  if (pcVar3 != param_1) {
    if (pcVar3 != (char *)0x0) {
      FUN_140035ac0(pcVar3);
    }
    *(undefined8 *)this = 0;
    if (param_1 != (char *)0x0) {
      cVar1 = *param_1;
      pcVar3 = param_1;
      while (cVar1 != '\0') {
        pcVar3 = pcVar3 + 1;
        cVar1 = *pcVar3;
      }
      puVar2 = (undefined8 *)_malloc_base((ulonglong)(pcVar3 + (1 - (longlong)param_1)));
      *(undefined8 **)this = puVar2;
      if (puVar2 != (undefined8 *)0x0) {
        FUN_1400316b0(puVar2,(undefined8 *)param_1,(ulonglong)(pcVar3 + (1 - (longlong)param_1)));
      }
    }
  }
  return this;
}


// FUNCTION_END

// FUNCTION_START: `scalar_deleting_destructor' @ 14002d920

/* Library Function - Single Match
    protected: virtual void * __ptr64 __cdecl std::locale::_Locimp::`scalar deleting
   destructor'(unsigned int) __ptr64
   
   Library: Visual Studio 2019 Release */

void * __thiscall std::locale::_Locimp::_scalar_deleting_destructor_(_Locimp *this,uint param_1)

{
  *(undefined ***)this = vftable;
  _Locimp_dtor(this);
  if (*(LPVOID *)(this + 0x28) != (LPVOID)0x0) {
    FUN_140035ac0(*(LPVOID *)(this + 0x28));
  }
  *(undefined8 *)(this + 0x28) = 0;
  *(undefined ***)this = _Facet_base::vftable;
  if ((param_1 & 1) != 0) {
    FUN_14002f180();
  }
  return this;
}


// FUNCTION_END

// FUNCTION_START: _Facet_Register @ 14002d97c

/* Library Function - Single Match
    void __cdecl std::_Facet_Register(class std::_Facet_base * __ptr64)
   
   Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release */

void __cdecl std::_Facet_Register(_Facet_base *param_1)

{
  undefined8 *puVar1;
  
  puVar1 = (undefined8 *)operator_new(0x10);
  if (puVar1 != (undefined8 *)0x0) {
    *puVar1 = DAT_14007be08;
    puVar1[1] = param_1;
  }
  DAT_14007be08 = puVar1;
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_14002d9b4 @ 14002d9b4