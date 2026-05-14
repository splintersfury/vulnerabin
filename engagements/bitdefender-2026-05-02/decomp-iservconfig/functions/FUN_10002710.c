void __fastcall FUN_10002710(int param_1)

{
  undefined4 *puVar1;
  
  if (*(int **)(param_1 + 4) != (int *)0x0) {
    puVar1 = (undefined4 *)(**(code **)(**(int **)(param_1 + 4) + 8))();
    if (puVar1 != (undefined4 *)0x0) {
      (**(code **)*puVar1)(1);
    }
  }
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_10002730 @ 10002730