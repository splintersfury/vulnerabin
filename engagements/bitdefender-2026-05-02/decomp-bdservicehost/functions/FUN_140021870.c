void FUN_140021870(void)

{
  code *pcVar1;
  
  FUN_14002d6f4(0x14006d740);
  pcVar1 = (code *)swi(3);
  (*pcVar1)();
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_140021890 @ 140021890