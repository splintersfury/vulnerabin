int * __thiscall FUN_1000ec10(void *this,int *param_1)

{
  void *pvVar1;
  code *pcVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  void *pvVar6;
  int *piVar7;
  
  if ((int *)this != param_1) {
    if (0xf < *(uint *)((int)this + 0x14)) {
                    /* WARNING: Load size is inaccurate */
      pvVar1 = *this;
      pvVar6 = pvVar1;
      if ((0xfff < *(uint *)((int)this + 0x14) + 1) &&
         (pvVar6 = *(void **)((int)pvVar1 + -4), 0x1f < (uint)((int)pvVar1 + (-4 - (int)pvVar6)))) {
        FUN_10032f7f();
        pcVar2 = (code *)swi(3);
        piVar7 = (int *)(*pcVar2)();
        return piVar7;
      }
      FUN_1002e346(pvVar6);
    }
    *(undefined4 *)((int)this + 0x10) = 0;
    *(undefined4 *)((int)this + 0x14) = 0xf;
    *(undefined1 *)this = 0;
    iVar3 = param_1[1];
    iVar4 = param_1[2];
    iVar5 = param_1[3];
    *(int *)this = *param_1;
    *(int *)((int)this + 4) = iVar3;
    *(int *)((int)this + 8) = iVar4;
    *(int *)((int)this + 0xc) = iVar5;
    *(undefined8 *)((int)this + 0x10) = *(undefined8 *)(param_1 + 4);
    param_1[4] = 0;
    param_1[5] = 0xf;
    *(undefined1 *)param_1 = 0;
  }
  return (int *)this;
}


// FUNCTION_END

// FUNCTION_START: `scalar_deleting_destructor' @ 1000ec90

/* Library Function - Single Match
    public: virtual void * __thiscall std::basic_stringstream<char,struct
   std::char_traits<char>,class std::allocator<char> >::`scalar deleting destructor'(unsigned int)
   
   Library: Visual Studio 2019 Release */

void * __thiscall
std::basic_stringstream<char,struct_std::char_traits<char>,class_std::allocator<char>_>::
_scalar_deleting_destructor_
          (basic_stringstream<char,struct_std::char_traits<char>,class_std::allocator<char>_> *this,
          uint param_1)

{
  basic_stringstream<char,struct_std::char_traits<char>,class_std::allocator<char>_> *pbVar1;
  
  pbVar1 = this + -0x68;
  FUN_1000de90((int *)pbVar1);
  if ((param_1 & 1) != 0) {
    FUN_1002e346(pbVar1);
  }
  return pbVar1;
}


// FUNCTION_END

// FUNCTION_START: FUN_1000ecc0 @ 1000ecc0