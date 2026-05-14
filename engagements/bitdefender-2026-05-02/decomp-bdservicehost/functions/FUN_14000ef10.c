ios_base * FUN_14000ef10(ios_base *param_1,uint param_2)

{
  FUN_14000e180((longlong)param_1);
  *(undefined ***)param_1 = std::ios_base::vftable;
  std::ios_base::_Ios_base_dtor(param_1);
  if ((param_2 & 1) != 0) {
    FUN_14002f180();
  }
  return param_1 + -0x88;
}


// FUNCTION_END

// FUNCTION_START: FID_conflict:`scalar_deleting_destructor' @ 14000ef70

/* Library Function - Multiple Matches With Different Base Names
    public: virtual void * __ptr64 __cdecl std::basic_ostream<char,struct std::char_traits<char>
   >::`scalar deleting destructor'(unsigned int) __ptr64
    public: virtual void * __ptr64 __cdecl std::basic_ostream<unsigned short,struct
   std::char_traits<unsigned short> >::`scalar deleting destructor'(unsigned int) __ptr64
    public: virtual void * __ptr64 __cdecl std::basic_ostream<wchar_t,struct
   std::char_traits<wchar_t> >::`scalar deleting destructor'(unsigned int) __ptr64
   
   Library: Visual Studio 2019 Release */