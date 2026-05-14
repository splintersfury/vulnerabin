void FUN_1002ca17(void)

{
  undefined4 *puVar1;
  
  while (puVar1 = DAT_1006a8e4, DAT_1006a8e4 != (undefined4 *)0x0) {
    DAT_1006a8e4 = (undefined4 *)*DAT_1006a8e4;
    FUN_1002c9e6((int)puVar1);
    FUN_1002e346(puVar1);
  }
  return;
}


// FUNCTION_END

// FUNCTION_START: ~_Locimp @ 1002ca3e

/* Library Function - Single Match
    protected: virtual __thiscall std::locale::_Locimp::~_Locimp(void)
   
   Library: Visual Studio 2019 Release */

void __thiscall std::locale::_Locimp::~_Locimp(_Locimp *this)

{
  *(undefined ***)this = vftable;
  _Locimp_dtor(this);
  if (*(int *)(this + 0x18) != 0) {
    FUN_100330ca(*(void **)(this + 0x18));
  }
  *(undefined4 *)(this + 0x18) = 0;
  *(undefined ***)this = _Facet_base::vftable;
  return;
}


// FUNCTION_END

// FUNCTION_START: operator= @ 1002ca69

/* Library Function - Single Match
    public: class std::_Yarn<char> & __thiscall std::_Yarn<char>::operator=(char const *)
   
   Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release */

_Yarn<char> * __thiscall std::_Yarn<char>::operator=(_Yarn<char> *this,char *param_1)

{
  char cVar1;
  uint *puVar2;
  char *pcVar3;
  
  if (*(char **)this != param_1) {
    if (*(int *)this != 0) {
      FUN_100330ca(*(void **)this);
    }
    *(undefined4 *)this = 0;
    if (param_1 != (char *)0x0) {
      cVar1 = *param_1;
      pcVar3 = param_1;
      while (cVar1 != '\0') {
        pcVar3 = pcVar3 + 1;
        cVar1 = *pcVar3;
      }
      puVar2 = (uint *)FUN_1003a007((size_t)(pcVar3 + (1 - (int)param_1)));
      *(uint **)this = puVar2;
      if (puVar2 != (uint *)0x0) {
        FUN_100301d0(puVar2,(uint *)param_1,(uint)(pcVar3 + (1 - (int)param_1)));
      }
    }
  }
  return this;
}


// FUNCTION_END

// FUNCTION_START: `scalar_deleting_destructor' @ 1002cabd

/* Library Function - Single Match
    protected: virtual void * __thiscall std::locale::_Locimp::`scalar deleting destructor'(unsigned
   int)
   
   Library: Visual Studio 2019 Release */

void * __thiscall std::locale::_Locimp::_scalar_deleting_destructor_(_Locimp *this,uint param_1)

{
  ~_Locimp(this);
  if ((param_1 & 1) != 0) {
    FUN_1002e346(this);
  }
  return this;
}


// FUNCTION_END

// FUNCTION_START: _Facet_Register @ 1002cadf

/* Library Function - Single Match
    void __cdecl std::_Facet_Register(class std::_Facet_base *)
   
   Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release */

void __cdecl std::_Facet_Register(_Facet_base *param_1)

{
  undefined4 *puVar1;
  
  puVar1 = (undefined4 *)operator_new(8);
  if (puVar1 == (undefined4 *)0x0) {
    puVar1 = (undefined4 *)0x0;
  }
  else {
    *puVar1 = DAT_1006a8e4;
    puVar1[1] = param_1;
  }
  DAT_1006a8e4 = puVar1;
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_1002cb0b @ 1002cb0b