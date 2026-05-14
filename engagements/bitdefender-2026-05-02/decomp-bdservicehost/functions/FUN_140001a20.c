void FUN_140001a20(void)

{
  code *pcVar1;
  
  FUN_14002d6f4(0x14006a920);
  pcVar1 = (code *)swi(3);
  (*pcVar1)();
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_140001a40 @ 140001a40