char * FUN_14002d7d0(int param_1)

{
  int *piVar1;
  
  piVar1 = &DAT_14005bfb0;
  do {
    if (*piVar1 == param_1) {
      return *(char **)(piVar1 + 2);
    }
    piVar1 = piVar1 + 4;
  } while (piVar1 != (int *)"address family not supported");
  return "unknown error";
}


// FUNCTION_END

// FUNCTION_START: FUN_14002d7f8 @ 14002d7f8