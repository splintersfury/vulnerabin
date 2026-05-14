void __fastcall FUN_1002c2b8(undefined4 param_1,undefined4 param_2)

{
  undefined4 in_EAX;
  uint unaff_EBP;
  undefined4 *unaff_ESI;
  undefined4 *unaff_EDI;
  undefined4 uStack0000000c;
  
  *unaff_EDI = param_2;
  unaff_EDI[1] = &PTR_vftable_10069aa8;
  *unaff_ESI = in_EAX;
  ExceptionList = *(void **)(unaff_EBP - 0xc);
  uStack0000000c = 0x1002c2dd;
  FUN_1002e315(*(uint *)(unaff_EBP - 0x14) ^ unaff_EBP);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_1002c2f0 @ 1002c2f0