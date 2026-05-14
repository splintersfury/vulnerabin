void * __thiscall FUN_100024f0(void *this,byte param_1)

{
  if ((param_1 & 1) != 0) {
    FUN_1002e346(this);
  }
  return this;
}


// FUNCTION_END

// FUNCTION_START: `scalar_deleting_destructor' @ 10002510

/* Library Function - Single Match
    public: virtual void * __thiscall std::_Facet_base::`scalar deleting destructor'(unsigned int)
   
   Library: Visual Studio 2019 Release */

void * __thiscall std::_Facet_base::_scalar_deleting_destructor_(_Facet_base *this,uint param_1)

{
  *(undefined ***)this = vftable;
  if ((param_1 & 1) != 0) {
    FUN_1002e346(this);
  }
  return this;
}


// FUNCTION_END

// FUNCTION_START: FUN_10002540 @ 10002540