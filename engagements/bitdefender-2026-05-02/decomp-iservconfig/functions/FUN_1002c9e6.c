void __fastcall FUN_1002c9e6(int param_1)

{
  code *pcVar1;
  undefined4 *puVar2;
  
  pcVar1 = *(code **)(**(int **)(param_1 + 4) + 8);
  (*(code *)PTR_guard_check_icall_10052220)();
  puVar2 = (undefined4 *)(*pcVar1)();
  if (puVar2 != (undefined4 *)0x0) {
    pcVar1 = *(code **)*puVar2;
    (*(code *)PTR_guard_check_icall_10052220)(1);
    (*pcVar1)();
  }
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_1002ca17 @ 1002ca17