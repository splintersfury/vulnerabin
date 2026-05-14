void FUN_14002d48c(void)

{
  int iVar1;
  int iVar2;
  LPCRITICAL_SECTION lpCriticalSection;
  
  LOCK();
  iVar2 = DAT_14007a000 + -1;
  UNLOCK();
  iVar1 = DAT_14007a000 + -1;
  DAT_14007a000 = iVar2;
  if (iVar1 < 0) {
    lpCriticalSection = (LPCRITICAL_SECTION)&DAT_14007bc80;
    do {
      DeleteCriticalSection(lpCriticalSection);
      lpCriticalSection = lpCriticalSection + 1;
    } while (lpCriticalSection != (LPCRITICAL_SECTION)&DAT_14007bdc0);
  }
  return;
}


// FUNCTION_END

// FUNCTION_START: ~_Lockit @ 14002d4c8

/* Library Function - Single Match
    public: __cdecl std::_Lockit::~_Lockit(void) __ptr64
   
   Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release */

void __thiscall std::_Lockit::~_Lockit(_Lockit *this)

{
  int iVar1;
  
  iVar1 = *(int *)this;
  if (iVar1 == 0) {
    FUN_14003f3f0();
    return;
  }
  if (iVar1 < 8) {
    LeaveCriticalSection((LPCRITICAL_SECTION)(&DAT_14007bc80 + (longlong)iVar1 * 0x28));
  }
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_14002d4fc @ 14002d4fc