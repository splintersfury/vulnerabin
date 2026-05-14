void FUN_10001eb0(void)

{
  code *pcVar1;
  
  FUN_1002c854("string too long");
  pcVar1 = (code *)swi(3);
  (*pcVar1)();
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_10001ec0 @ 10001ec0