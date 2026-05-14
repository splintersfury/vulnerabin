uint * __thiscall FUN_100056d0(void *this,uint *param_1)

{
  uint uVar1;
  code *pcVar2;
  uint uVar3;
  void *pvVar4;
  uint uVar5;
  uint *puVar6;
  uint uVar7;
  
  *(undefined4 *)this = 0;
  *(undefined4 *)((int)this + 0x10) = 0;
  *(undefined4 *)((int)this + 0x14) = 0;
  uVar1 = param_1[4];
  if (0xf < param_1[5]) {
    param_1 = (uint *)*param_1;
  }
  if (uVar1 < 0x10) {
    uVar7 = param_1[1];
    uVar5 = param_1[2];
    uVar3 = param_1[3];
    *(uint *)this = *param_1;
    *(uint *)((int)this + 4) = uVar7;
    *(uint *)((int)this + 8) = uVar5;
    *(uint *)((int)this + 0xc) = uVar3;
    *(uint *)((int)this + 0x10) = uVar1;
    *(undefined4 *)((int)this + 0x14) = 0xf;
    return (uint *)this;
  }
  uVar7 = uVar1 | 0xf;
  if (0x7fffffff < uVar7) {
    uVar7 = 0x7fffffff;
  }
  uVar5 = -(uint)(0xfffffffe < uVar7) | uVar7 + 1;
  if (0xfff < uVar5) {
    if (uVar5 < uVar5 + 0x23) {
      pvVar4 = operator_new(uVar5 + 0x23);
      if (pvVar4 != (void *)0x0) {
        puVar6 = (uint *)((int)pvVar4 + 0x23U & 0xffffffe0);
        puVar6[-1] = (uint)pvVar4;
        goto LAB_10005773;
      }
    }
    else {
      FUN_10001fb0();
    }
    FUN_10032f7f();
    pcVar2 = (code *)swi(3);
    puVar6 = (uint *)(*pcVar2)();
    return puVar6;
  }
  if (uVar5 == 0) {
    puVar6 = (uint *)0x0;
  }
  else {
    puVar6 = (uint *)operator_new(uVar5);
  }
LAB_10005773:
  *(uint **)this = puVar6;
  FUN_100301d0(puVar6,param_1,uVar1 + 1);
  *(uint *)((int)this + 0x10) = uVar1;
  *(uint *)((int)this + 0x14) = uVar7;
  return (uint *)this;
}


// FUNCTION_END

// FUNCTION_START: `scalar_deleting_destructor' @ 100057b0

/* Library Function - Single Match
    public: virtual void * __thiscall std::basic_stringbuf<char,struct std::char_traits<char>,class
   std::allocator<char> >::`scalar deleting destructor'(unsigned int)
   
   Library: Visual Studio 2019 Release */

void * __thiscall
std::basic_stringbuf<char,struct_std::char_traits<char>,class_std::allocator<char>_>::
_scalar_deleting_destructor_
          (basic_stringbuf<char,struct_std::char_traits<char>,class_std::allocator<char>_> *this,
          uint param_1)

{
  FUN_10004db0((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    FUN_1002e346(this);
  }
  return this;
}


// FUNCTION_END

// FUNCTION_START: `scalar_deleting_destructor' @ 100057e0

/* Library Function - Single Match
    public: virtual void * __thiscall std::basic_streambuf<char,struct std::char_traits<char>
   >::`scalar deleting destructor'(unsigned int)
   
   Library: Visual Studio 2019 Release */

void * __thiscall
std::basic_streambuf<char,struct_std::char_traits<char>_>::_scalar_deleting_destructor_
          (basic_streambuf<char,struct_std::char_traits<char>_> *this,uint param_1)

{
  void *pvVar1;
  undefined4 *puVar2;
  
  pvVar1 = *(void **)(this + 0x34);
  *(undefined ***)this = basic_streambuf<wchar_t,struct_std::char_traits<wchar_t>_>::vftable;
  if (pvVar1 != (void *)0x0) {
    if (*(int **)((int)pvVar1 + 4) != (int *)0x0) {
      puVar2 = (undefined4 *)(**(code **)(**(int **)((int)pvVar1 + 4) + 8))();
      if (puVar2 != (undefined4 *)0x0) {
        (**(code **)*puVar2)(1);
      }
    }
    FUN_1002e346(pvVar1);
  }
  if ((param_1 & 1) != 0) {
    FUN_1002e346(this);
  }
  return this;
}


// FUNCTION_END

// FUNCTION_START: FUN_10005830 @ 10005830