void FUN_10017fa0(void)

{
  code *pcVar1;
  
  FUN_1002c854("vector too long");
  pcVar1 = (code *)swi(3);
  (*pcVar1)();
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_10017fb0 @ 10017fb0