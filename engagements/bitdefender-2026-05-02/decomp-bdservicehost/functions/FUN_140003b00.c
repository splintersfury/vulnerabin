char * FUN_140003b00(void)

{
  return "Bad optional access";
}


// FUNCTION_END

// FUNCTION_START: _Throw_parallelism_resources_exhausted @ 140003b10

/* Library Function - Single Match
    void __cdecl std::_Throw_parallelism_resources_exhausted(void)
   
   Library: Visual Studio 2019 Release */

void __cdecl std::_Throw_parallelism_resources_exhausted(void)

{
  undefined8 local_28;
  undefined8 uStack_20;
  undefined8 local_18;
  
  local_28 = 0;
  uStack_20 = 0;
  local_18 = 0;
  _Parallelism_resources_exhausted::_Parallelism_resources_exhausted
            ((_Parallelism_resources_exhausted *)&local_28);
                    /* WARNING: Subroutine does not return */
  _CxxThrowException(&local_28,(ThrowInfo *)&DAT_1400778f0);
}


// FUNCTION_END

// FUNCTION_START: _Parallelism_resources_exhausted @ 140003b40

/* Library Function - Single Match
    public: __cdecl std::_Parallelism_resources_exhausted::_Parallelism_resources_exhausted(void)
   __ptr64
   
   Library: Visual Studio 2019 Release */

_Parallelism_resources_exhausted * __thiscall
std::_Parallelism_resources_exhausted::_Parallelism_resources_exhausted
          (_Parallelism_resources_exhausted *this)

{
  *(undefined8 *)(this + 8) = 0;
  *(undefined8 *)(this + 0x10) = 0;
  *(undefined ***)this = bad_optional_access::vftable;
  return this;
}


// FUNCTION_END

// FUNCTION_START: FUN_140003b60 @ 140003b60