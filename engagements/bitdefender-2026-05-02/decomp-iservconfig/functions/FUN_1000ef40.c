undefined4 * __thiscall FUN_1000ef40(void *this,int param_1)

{
  *(undefined ***)this = std::exception::vftable;
  *(undefined8 *)((int)this + 4) = 0;
  ___std_exception_copy((undefined4 *)(param_1 + 4),(undefined4 *)((int)this + 4));
  *(undefined ***)this = nlohmann::detail::exception::vftable;
  *(undefined4 *)((int)this + 0xc) = *(undefined4 *)(param_1 + 0xc);
  *(undefined ***)((int)this + 0x10) = std::exception::vftable;
  *(undefined8 *)((int)this + 0x14) = 0;
  ___std_exception_copy((undefined4 *)(param_1 + 0x14),(undefined4 *)((int)this + 0x14));
  *(undefined ***)((int)this + 0x10) = std::runtime_error::vftable;
  *(undefined ***)this = nlohmann::detail::type_error::vftable;
  return (undefined4 *)this;
}


// FUNCTION_END

// FUNCTION_START: `scalar_deleting_destructor' @ 1000efb0

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
  *(undefined ***)this = vftable;
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

// FUNCTION_START: FUN_1000f000 @ 1000f000