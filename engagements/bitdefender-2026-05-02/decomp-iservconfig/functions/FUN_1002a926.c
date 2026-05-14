void FUN_1002a926(void)

{
  undefined4 uVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  undefined4 uVar4;
  uint unaff_EBP;
  undefined4 *unaff_ESI;
  undefined4 uStack00000008;
  
  uVar1 = *(undefined4 *)(unaff_EBP - 0x70);
  uVar2 = *(undefined4 *)(unaff_EBP - 0x6c);
  uVar3 = *(undefined4 *)(unaff_EBP - 0x68);
  uVar4 = *(undefined4 *)(unaff_EBP - 100);
  *unaff_ESI = 0;
  unaff_ESI[4] = 0;
  unaff_ESI[5] = 0;
  *unaff_ESI = uVar1;
  unaff_ESI[1] = uVar2;
  unaff_ESI[2] = uVar3;
  unaff_ESI[3] = uVar4;
  *(undefined8 *)(unaff_ESI + 4) = *(undefined8 *)(unaff_EBP - 0x60);
  FUN_1000c320(unaff_EBP - 0x498);
  ExceptionList = *(void **)(unaff_EBP - 0xc);
  uStack00000008 = 0x1002a96f;
  FUN_1002e315(*(uint *)(unaff_EBP - 0x1c) ^ unaff_EBP);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_1002a9e0 @ 1002a9e0