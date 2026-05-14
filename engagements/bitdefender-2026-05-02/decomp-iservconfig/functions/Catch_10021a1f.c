undefined * Catch_10021a1f(void)

{
  uint *puVar1;
  undefined4 *puVar2;
  int unaff_EBP;
  uint in_stack_ffffffe8;
  undefined4 in_stack_ffffffec;
  undefined4 in_stack_fffffff0;
  undefined4 uVar3;
  char *pcVar4;
  undefined4 uVar5;
  
  puVar1 = (uint *)(**(code **)(**(int **)(unaff_EBP + -0x84) + 4))();
  uVar5 = 0x18;
  *(undefined4 *)(unaff_EBP + -0x68) = 0;
  pcVar4 = "invalid json from file: ";
  *(undefined4 *)(unaff_EBP + -0x58) = 0;
  *(undefined4 *)(unaff_EBP + -0x54) = 0xf;
  *(undefined1 *)(unaff_EBP + -0x68) = 0;
  uVar3 = 0x10021a59;
  FUN_10008e70((void *)(unaff_EBP + -0x68),(uint *)"invalid json from file: ",0x18);
  *(undefined1 *)(unaff_EBP + -4) = 4;
  FUN_10014250((uint *)&stack0xffffffe8,(void *)(unaff_EBP + -0x68),puVar1);
  puVar2 = FUN_10014860((void *)(unaff_EBP + -0xc4),in_stack_ffffffe8,in_stack_ffffffec,
                        in_stack_fffffff0,uVar3,CONCAT44(uVar5,pcVar4));
  puVar2 = FUN_100143d0((undefined4 *)(unaff_EBP + -0xa4),puVar2);
  FUN_100146a0(*(void **)(unaff_EBP + -0x44),puVar2);
  FUN_1000bd80(unaff_EBP + -0xa4);
  FUN_1000bd80(unaff_EBP + -0xc4);
  FUN_10008fa0((int *)(unaff_EBP + -0x68));
  return &DAT_10021ab6;
}


// FUNCTION_END

// FUNCTION_START: FUN_10021ac4 @ 10021ac4