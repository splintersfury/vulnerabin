void __cdecl tidy_global(void)

{
  _Lockit local_8 [4];
  
  std::_Lockit::_Lockit(local_8,0);
  __Deletegloballocale(&DAT_1006a8ec);
  DAT_1006a8ec = 0;
  FUN_1002c986((int *)local_8);
  return;
}


// FUNCTION_END

// FUNCTION_START: __Getctype @ 1002cd26

/* Library Function - Single Match
    __Getctype
   
   Library: Visual Studio 2019 Release */