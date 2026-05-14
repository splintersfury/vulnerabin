void __fastcall FUN_1001bd20(undefined4 *param_1)

{
  char *pcVar1;
  char *pcVar2;
  
  pcVar1 = (char *)param_1[1];
  for (pcVar2 = (char *)*param_1; pcVar2 != pcVar1; pcVar2 = pcVar2 + 0x10) {
    FUN_1000e760(pcVar2);
  }
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_1001bd50 @ 1001bd50