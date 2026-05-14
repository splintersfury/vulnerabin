void FUN_140026150(undefined8 param_1,char *param_2,char *param_3)

{
  if (param_2 != param_3) {
    do {
      FUN_14001cf70(param_2);
      param_2 = param_2 + 0x10;
    } while (param_2 != param_3);
  }
  return;
}


// FUNCTION_END

// FUNCTION_START: deallocate @ 140026190

/* Library Function - Single Match
    public: static void __cdecl std::_Default_allocator_traits<class std::allocator<struct
   std::_Container_proxy> >::deallocate(class std::allocator<struct std::_Container_proxy> &
   __ptr64,struct std::_Container_proxy * __ptr64 const,unsigned __int64)
   
   Library: Visual Studio 2017 Release */

void __cdecl
std::_Default_allocator_traits<class_std::allocator<struct_std::_Container_proxy>_>::deallocate
          (allocator<struct_std::_Container_proxy> *param_1,_Container_proxy *param_2,
          __uint64 param_3)

{
  code *pcVar1;
  
  if ((0xfff < param_3 << 4) &&
     ((_Container_proxy *)0x1f < param_2 + (-8 - *(longlong *)(param_2 + -8)))) {
    FUN_140035d28();
    pcVar1 = (code *)swi(3);
    (*pcVar1)();
    return;
  }
  FUN_14002f180();
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_1400261e0 @ 1400261e0