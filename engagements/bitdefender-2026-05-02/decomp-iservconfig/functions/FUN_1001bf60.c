void __fastcall FUN_1001bf60(char *param_1,uint param_2)

{
  uint uVar1;
  uint *puVar2;
  undefined1 local_c [4];
  uint local_8;
  
  local_8 = DAT_10069054 ^ (uint)&stack0xfffffffc;
  puVar2 = (uint *)((int)local_c + 1);
  do {
    puVar2 = (uint *)((int)puVar2 + -1);
    uVar1 = param_2 / 10;
    *(char *)puVar2 = (char)param_2 + (char)uVar1 * -10 + '0';
    param_2 = uVar1;
  } while (uVar1 != 0);
  param_1[0] = '\0';
  param_1[1] = '\0';
  param_1[2] = '\0';
  param_1[3] = '\0';
  param_1[0x10] = '\0';
  param_1[0x11] = '\0';
  param_1[0x12] = '\0';
  param_1[0x13] = '\0';
  param_1[0x14] = '\x0f';
  param_1[0x15] = '\0';
  param_1[0x16] = '\0';
  param_1[0x17] = '\0';
  *param_1 = (char)uVar1;
  if (puVar2 != (uint *)((int)local_c + 1U)) {
    FUN_10008e70(param_1,puVar2,((int)local_c + 1U) - (int)puVar2);
  }
  FUN_1002e315(local_8 ^ (uint)&stack0xfffffffc);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_1001bfe0 @ 1001bfe0