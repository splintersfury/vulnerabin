undefined1 * __fastcall FUN_1001bcd0(undefined1 *param_1,undefined1 *param_2,undefined1 *param_3)

{
  undefined4 uVar1;
  undefined1 *puVar2;
  undefined1 *puVar3;
  
  puVar2 = param_1;
  puVar3 = param_3;
  if (param_1 != param_2) {
    do {
      *puVar3 = *puVar2;
      puVar3 = puVar3 + 0x10;
      uVar1 = *(undefined4 *)(puVar2 + 0xc);
      *(undefined4 *)(puVar2 + (int)(param_3 + (8 - (int)param_1))) = *(undefined4 *)(puVar2 + 8);
      *(undefined4 *)(puVar2 + (int)(param_3 + (0xc - (int)param_1))) = uVar1;
      *puVar2 = 0;
      *(undefined4 *)(puVar2 + 8) = 0;
      *(undefined4 *)(puVar2 + 0xc) = 0;
      puVar2 = puVar2 + 0x10;
    } while (puVar2 != param_2);
  }
  return puVar3;
}


// FUNCTION_END

// FUNCTION_START: FUN_1001bd20 @ 1001bd20