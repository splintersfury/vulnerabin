int FUN_1000b430(uint *param_1,int param_2,undefined4 param_3,uint *param_4)

{
  FUN_100301d0(param_4,param_1,param_2 - (int)param_1);
  return param_2;
}


// FUNCTION_END

// FUNCTION_START: `scalar_deleting_destructor' @ 1000b460

/* Library Function - Single Match
    protected: virtual void * __thiscall std::ctype<char>::`scalar deleting destructor'(unsigned
   int)
   
   Library: Visual Studio 2019 Release */

void * __thiscall std::ctype<char>::_scalar_deleting_destructor_(ctype<char> *this,uint param_1)

{
  *(undefined ***)this = vftable;
  if (*(int *)(this + 0x10) < 1) {
    if (*(int *)(this + 0x10) < 0) {
      thunk_FUN_100330ca(*(void **)(this + 0xc));
    }
  }
  else {
    FUN_100330ca(*(void **)(this + 0xc));
  }
  FUN_100330ca(*(void **)(this + 0x14));
  *(undefined ***)this = _Facet_base::vftable;
  if ((param_1 & 1) != 0) {
    FUN_1002e346(this);
  }
  return this;
}


// FUNCTION_END

// FUNCTION_START: FUN_1000b4c0 @ 1000b4c0