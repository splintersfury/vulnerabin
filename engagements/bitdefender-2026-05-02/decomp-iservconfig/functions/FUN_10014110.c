void FUN_10014110(void)

{
  code *pcVar1;
  
  FUN_1002c854("vector<bool> too long");
  pcVar1 = (code *)swi(3);
  (*pcVar1)();
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_10014120 @ 10014120