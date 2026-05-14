void __fastcall FUN_1000b500(int *param_1)

{
  int *piVar1;
  
  piVar1 = (int *)param_1[9];
  if (piVar1 != (int *)0x0) {
    (**(code **)(*piVar1 + 0x10))(piVar1 != param_1);
    param_1[9] = 0;
  }
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_1000b530 @ 1000b530