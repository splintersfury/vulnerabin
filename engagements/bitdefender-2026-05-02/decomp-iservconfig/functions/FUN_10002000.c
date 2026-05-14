char * __fastcall FUN_10002000(int param_1)

{
  char *pcVar1;
  
  pcVar1 = "Unknown exception";
  if (*(char **)(param_1 + 4) != (char *)0x0) {
    pcVar1 = *(char **)(param_1 + 4);
  }
  return pcVar1;
}


// FUNCTION_END

// FUNCTION_START: FUN_10002010 @ 10002010