void FUN_1000bd02(void)

{
  uint unaff_EBP;
  undefined4 uStack00000008;
  
  ExceptionList = *(void **)(unaff_EBP - 0xc);
  uStack00000008 = 0x1000bd19;
  FUN_1002e315(*(uint *)(unaff_EBP - 0x1c) ^ unaff_EBP);
  return;
}


// FUNCTION_END

// FUNCTION_START: thunk_FUN_1000e5a0 @ 1000bd70