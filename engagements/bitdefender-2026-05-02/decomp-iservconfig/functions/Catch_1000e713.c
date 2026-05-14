void Catch_1000e713(void)

{
  uint *puVar1;
  int unaff_EBP;
  
  puVar1 = FUN_10014120((uint *)(unaff_EBP + -0x2c),(uint *)"key \'",*(uint **)(unaff_EBP + 8));
  *(undefined1 *)(unaff_EBP + -4) = 2;
  puVar1 = FUN_10014250((uint *)(unaff_EBP + -0x7c),puVar1,(uint *)"\' not found");
  *(undefined1 *)(unaff_EBP + -4) = 3;
  FUN_1000af70((undefined4 *)(unaff_EBP + -0x48),0x193,puVar1);
                    /* WARNING: Subroutine does not return */
  __CxxThrowException_8((int *)(unaff_EBP + -0x48),&DAT_10067618);
}


// FUNCTION_END

// FUNCTION_START: FUN_1000e760 @ 1000e760