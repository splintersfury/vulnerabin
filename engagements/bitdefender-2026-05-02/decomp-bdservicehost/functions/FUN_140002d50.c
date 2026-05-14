undefined8 * FUN_140002d50(undefined8 *param_1,longlong param_2)

{
  undefined8 uVar1;
  undefined8 uVar2;
  
  *param_1 = std::exception::vftable;
  param_1[1] = 0;
  param_1[2] = 0;
  __std_exception_copy((longlong *)(param_2 + 8),param_1 + 1);
  *param_1 = std::_System_error::vftable;
  uVar1 = *(undefined8 *)(param_2 + 0x18);
  uVar2 = *(undefined8 *)(param_2 + 0x20);
  *param_1 = std::ios_base::failure::vftable;
  param_1[3] = uVar1;
  param_1[4] = uVar2;
  return param_1;
}


// FUNCTION_END

// FUNCTION_START: `scalar_deleting_destructor' @ 140002db0

/* Library Function - Single Match
    public: virtual void * __ptr64 __cdecl std::ios_base::`scalar deleting destructor'(unsigned int)
   __ptr64
   
   Library: Visual Studio 2019 Release */

void * __thiscall std::ios_base::_scalar_deleting_destructor_(ios_base *this,uint param_1)

{
  *(undefined ***)this = vftable;
  _Ios_base_dtor(this);
  if ((param_1 & 1) != 0) {
    FUN_14002f180();
  }
  return this;
}


// FUNCTION_END

// FUNCTION_START: FUN_140002df0 @ 140002df0