void FUN_10007f70(void)

{
  code *pcVar1;
  
  FUN_1002c874("invalid string position");
  pcVar1 = (code *)swi(3);
  (*pcVar1)();
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_10007f80 @ 10007f80