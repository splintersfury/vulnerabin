void __cdecl __Deletegloballocale(int *param_1)

{
  code *pcVar1;
  undefined4 *puVar2;
  
  if ((int *)*param_1 != (int *)0x0) {
    pcVar1 = *(code **)(*(int *)*param_1 + 8);
    (*(code *)PTR_guard_check_icall_10052220)();
    puVar2 = (undefined4 *)(*pcVar1)();
    if (puVar2 != (undefined4 *)0x0) {
      pcVar1 = *(code **)*puVar2;
      (*(code *)PTR_guard_check_icall_10052220)(1);
      (*pcVar1)();
    }
  }
  return;
}


// FUNCTION_END

// FUNCTION_START: tidy_global @ 1002ccfc

/* Library Function - Single Match
    _tidy_global
   
   Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release */