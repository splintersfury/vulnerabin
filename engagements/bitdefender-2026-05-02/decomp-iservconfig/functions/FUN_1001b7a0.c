void __fastcall FUN_1001b7a0(undefined4 *param_1)

{
  int *piVar1;
  
  piVar1 = (int *)param_1[1];
  if (piVar1 != (int *)0x0) {
    FUN_1001b620(*param_1,*(int **)(*piVar1 + 4));
    FUN_1002e346((void *)*piVar1);
  }
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_1001b7d0 @ 1001b7d0