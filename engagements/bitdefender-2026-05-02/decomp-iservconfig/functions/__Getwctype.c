short __cdecl __Getwctype(wchar_t param_1,_Ctypevec *param_2)

{
  BOOL BVar1;
  ushort local_8 [2];
  
  BVar1 = GetStringTypeW(1,&param_1,1,local_8);
  return -(ushort)(BVar1 != 0) & local_8[0];
}


// FUNCTION_END

// FUNCTION_START: __Getwctypes @ 1002d107

/* Library Function - Single Match
    __Getwctypes
   
   Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release */