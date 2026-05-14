char * FUN_1002c8b4(void)

{
  return "bad function call";
}


// FUNCTION_END

// FUNCTION_START: _Syserror_map @ 1002c8ba

/* Library Function - Single Match
    char const * __cdecl std::_Syserror_map(int)
   
   Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release */

char * __cdecl std::_Syserror_map(int param_1)

{
  int *piVar1;
  
  piVar1 = &DAT_100525c0;
  do {
    if (*piVar1 == param_1) {
      return (char *)piVar1[1];
    }
    piVar1 = piVar1 + 2;
  } while (piVar1 != (int *)"address family not supported");
  return "unknown error";
}


// FUNCTION_END

// FUNCTION_START: _Winerror_map @ 1002c8df

/* Library Function - Single Match
    int __cdecl std::_Winerror_map(int)
   
   Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release */

int __cdecl std::_Winerror_map(int param_1)

{
  int *piVar1;
  
  piVar1 = &DAT_10052348;
  do {
    if (*piVar1 == param_1) {
      return piVar1[1];
    }
    piVar1 = piVar1 + 2;
  } while (piVar1 != &DAT_100525c0);
  return 0;
}


// FUNCTION_END

// FUNCTION_START: FUN_1002c901 @ 1002c901