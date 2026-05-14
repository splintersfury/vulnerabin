undefined4 Catch_All_10007f0b(void)

{
  return 0x10007ef9;
}


// FUNCTION_END

// FUNCTION_START: `scalar_deleting_destructor' @ 10007f20

/* Library Function - Single Match
    protected: virtual void * __thiscall std::numpunct<char>::`scalar deleting destructor'(unsigned
   int)
   
   Library: Visual Studio 2019 Release */

void * __thiscall
std::numpunct<char>::_scalar_deleting_destructor_(numpunct<char> *this,uint param_1)

{
  *(undefined ***)this = numpunct<wchar_t>::vftable;
  FUN_100330ca(*(void **)(this + 8));
  FUN_100330ca(*(void **)(this + 0x10));
  FUN_100330ca(*(void **)(this + 0x14));
  *(undefined ***)this = _Facet_base::vftable;
  if ((param_1 & 1) != 0) {
    FUN_1002e346(this);
  }
  return this;
}


// FUNCTION_END

// FUNCTION_START: FUN_10007f70 @ 10007f70