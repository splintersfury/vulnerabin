short __cdecl _Getwctype(wchar_t param_1,_Ctypevec *param_2)

{
  BOOL BVar1;
  wchar_t local_res8 [8];
  ushort local_res18 [8];
  
  local_res8[0] = param_1;
  BVar1 = GetStringTypeW(1,local_res8,1,local_res18);
  return -(ushort)(BVar1 != 0) & local_res18[0];
}


// FUNCTION_END

// FUNCTION_START: _Getwctypes @ 14002e164

/* Library Function - Single Match
    _Getwctypes
   
   Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release */