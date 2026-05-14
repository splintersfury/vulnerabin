void * __fastcall FUN_1000fca0(int param_1)

{
  int *piVar1;
  int iVar2;
  int *piVar3;
  code *pcVar4;
  void *pvVar5;
  void *pvVar6;
  
  if (0xf < *(uint *)(param_1 + 0x3c)) {
    pvVar6 = *(void **)(param_1 + 0x28);
    pvVar5 = pvVar6;
    if ((0xfff < *(uint *)(param_1 + 0x3c) + 1) &&
       (pvVar5 = *(void **)((int)pvVar6 + -4), 0x1f < (uint)((int)pvVar6 + (-4 - (int)pvVar5))))
    goto LAB_1000fd5c;
    FUN_1002e346(pvVar5);
  }
  *(undefined4 *)(param_1 + 0x38) = 0;
  *(undefined4 *)(param_1 + 0x3c) = 0xf;
  *(undefined1 *)(param_1 + 0x28) = 0;
  pvVar6 = *(void **)(param_1 + 0x1c);
  if (pvVar6 != (void *)0x0) {
    pvVar5 = pvVar6;
    if ((0xfff < (uint)(*(int *)(param_1 + 0x24) - (int)pvVar6)) &&
       (pvVar5 = *(void **)((int)pvVar6 + -4), 0x1f < (uint)((int)pvVar6 + (-4 - (int)pvVar5)))) {
LAB_1000fd5c:
      FUN_10032f7f();
      pcVar4 = (code *)swi(3);
      pvVar6 = (void *)(*pcVar4)();
      return pvVar6;
    }
    pvVar6 = (void *)FUN_1002e346(pvVar5);
    *(undefined4 *)(param_1 + 0x1c) = 0;
    *(undefined4 *)(param_1 + 0x20) = 0;
    *(undefined4 *)(param_1 + 0x24) = 0;
  }
  piVar3 = *(int **)(param_1 + 4);
  if (piVar3 != (int *)0x0) {
    LOCK();
    piVar1 = piVar3 + 1;
    iVar2 = *piVar1;
    pvVar6 = (void *)*piVar1;
    *piVar1 = iVar2 + -1;
    UNLOCK();
    if (iVar2 + -1 == 0) {
      pvVar6 = (void *)(**(code **)*piVar3)();
      LOCK();
      piVar1 = piVar3 + 2;
      iVar2 = *piVar1;
      *piVar1 = *piVar1 + -1;
      UNLOCK();
      if (iVar2 == 1) {
                    /* WARNING: Could not recover jumptable at 0x1000fd56. Too many branches */
                    /* WARNING: Treating indirect jump as call */
        pvVar6 = (void *)(**(code **)(*piVar3 + 4))();
        return pvVar6;
      }
    }
  }
  return pvVar6;
}


// FUNCTION_END

// FUNCTION_START: imbue @ 1000fd70

/* Library Function - Single Match
    protected: virtual void __thiscall std::basic_filebuf<char,struct std::char_traits<char>
   >::imbue(class std::locale const &)
   
   Library: Visual Studio 2019 Release */

void __thiscall
std::basic_filebuf<char,struct_std::char_traits<char>_>::imbue
          (basic_filebuf<char,struct_std::char_traits<char>_> *this,locale *param_1)

{
  codecvt<char,char,struct__Mbstatet> *pcVar1;
  
  pcVar1 = (codecvt<char,char,struct__Mbstatet> *)FUN_10014c00((_Facet_base *)param_1);
  _Initcvt(this,pcVar1);
  return;
}


// FUNCTION_END

// FUNCTION_START: sync @ 1000fd90

/* Library Function - Single Match
    protected: virtual int __thiscall std::basic_filebuf<char,struct std::char_traits<char>
   >::sync(void)
   
   Library: Visual Studio 2019 Release */

int __thiscall
std::basic_filebuf<char,struct_std::char_traits<char>_>::sync
          (basic_filebuf<char,struct_std::char_traits<char>_> *this)

{
  int iVar1;
  
  if (*(int *)(this + 0x4c) != 0) {
    iVar1 = (**(code **)(*(int *)this + 0xc))(0xffffffff);
    if (iVar1 != -1) {
      iVar1 = _fflush(*(FILE **)(this + 0x4c));
      if (iVar1 < 0) {
        return -1;
      }
    }
  }
  return 0;
}


// FUNCTION_END

// FUNCTION_START: setbuf @ 1000fdc0

/* Library Function - Single Match
    protected: virtual class std::basic_streambuf<char,struct std::char_traits<char> > * __thiscall
   std::basic_filebuf<char,struct std::char_traits<char> >::setbuf(char *,__int64)
   
   Library: Visual Studio 2019 Release */

basic_streambuf<char,struct_std::char_traits<char>_> * __thiscall
std::basic_filebuf<char,struct_std::char_traits<char>_>::setbuf
          (basic_filebuf<char,struct_std::char_traits<char>_> *this,char *param_1,__int64 param_2)

{
  int iVar1;
  size_t in_stack_00000008;
  
  if ((param_1 == (char *)0x0) && (in_stack_00000008 == 0 && (int)param_2 == 0)) {
    iVar1 = 4;
  }
  else {
    iVar1 = 0;
  }
  if (*(int *)(this + 0x4c) != 0) {
    iVar1 = _setvbuf(*(FILE **)(this + 0x4c),param_1,iVar1,in_stack_00000008);
    if (iVar1 == 0) {
      FUN_10011a70(this,*(int *)(this + 0x4c),1);
      return (basic_streambuf<char,struct_std::char_traits<char>_> *)this;
    }
  }
  return (basic_streambuf<char,struct_std::char_traits<char>_> *)0x0;
}


// FUNCTION_END

// FUNCTION_START: FUN_1000fe20 @ 1000fe20