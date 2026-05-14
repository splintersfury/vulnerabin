void FUN_14002a480(undefined8 *param_1)

{
  char *pcVar1;
  char *pcVar2;
  
  pcVar1 = (char *)param_1[1];
  for (pcVar2 = (char *)*param_1; pcVar2 != pcVar1; pcVar2 = pcVar2 + 0x10) {
    FUN_14001cf70(pcVar2);
  }
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_14002a4c0 @ 14002a4c0