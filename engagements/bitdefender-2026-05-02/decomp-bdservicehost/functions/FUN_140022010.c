void FUN_140022010(undefined8 param_1,undefined8 *param_2)

{
  undefined8 *puVar1;
  code *pcVar2;
  undefined8 *puVar3;
  
  *(undefined8 *)param_2[1] = 0;
  puVar3 = (undefined8 *)*param_2;
  do {
    if (puVar3 == (undefined8 *)0x0) {
      return;
    }
    puVar1 = (undefined8 *)*puVar3;
    if (0xf < (ulonglong)puVar3[5]) {
      if ((0xfff < puVar3[5] + 1) && (0x1f < (puVar3[2] - *(longlong *)(puVar3[2] + -8)) - 8U)) {
        FUN_140035d28();
        pcVar2 = (code *)swi(3);
        (*pcVar2)();
        return;
      }
      FUN_14002f180();
    }
    puVar3[4] = 0;
    puVar3[5] = 0xf;
    *(undefined1 *)(puVar3 + 2) = 0;
    FUN_14002f180();
    puVar3 = puVar1;
  } while( true );
}


// FUNCTION_END

// FUNCTION_START: FUN_1400220b0 @ 1400220b0