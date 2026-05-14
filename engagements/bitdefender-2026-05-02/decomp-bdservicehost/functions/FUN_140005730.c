bool FUN_140005730(uint *param_1)

{
  uint *puVar1;
  longlong lVar2;
  uint *puVar3;
  
  puVar3 = param_1;
  if (7 < *(ulonglong *)(param_1 + 6)) {
    puVar3 = *(uint **)param_1;
  }
  lVar2 = *(longlong *)(param_1 + 4) * 2 >> 1;
  if ((1 < lVar2) && ((*puVar3 & 0xffffffdf) - 0x3a0041 < 0x1a)) {
    if ((2 < lVar2) && (((short)puVar3[1] == 0x5c || ((short)puVar3[1] == 0x2f)))) {
      return true;
    }
    return false;
  }
  puVar1 = FUN_140005400(puVar3,(uint *)(*(longlong *)(param_1 + 4) * 2 + (longlong)puVar3));
  return puVar3 != puVar1;
}


// FUNCTION_END

// FUNCTION_START: _Tidy_deallocate @ 1400057a0

/* Library Function - Single Match
    public: void __cdecl std::basic_string<wchar_t,struct std::char_traits<wchar_t>,class
   std::allocator<wchar_t> >::_Tidy_deallocate(void) __ptr64
   
   Library: Visual Studio 2017 Release */

void __thiscall
std::basic_string<wchar_t,struct_std::char_traits<wchar_t>,class_std::allocator<wchar_t>_>::
_Tidy_deallocate(basic_string<wchar_t,struct_std::char_traits<wchar_t>,class_std::allocator<wchar_t>_>
                 *this)

{
  code *pcVar1;
  
  if (7 < *(ulonglong *)(this + 0x18)) {
    if ((0xfff < *(ulonglong *)(this + 0x18) * 2 + 2) &&
       (0x1f < (*(longlong *)this - *(longlong *)(*(longlong *)this + -8)) - 8U)) {
      FUN_140035d28();
      pcVar1 = (code *)swi(3);
      (*pcVar1)();
      return;
    }
    FUN_14002f180();
  }
  *(undefined8 *)(this + 0x18) = 7;
  *(undefined8 *)(this + 0x10) = 0;
  *(undefined2 *)this = 0;
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_140005810 @ 140005810

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */