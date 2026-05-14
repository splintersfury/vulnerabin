void __fastcall FUN_1000e760(char *param_1)

{
  char cVar1;
  int *piVar2;
  void *pvVar3;
  code *pcVar4;
  void *pvVar5;
  
  cVar1 = *param_1;
  if (cVar1 == '\x01') {
    piVar2 = *(int **)(param_1 + 8);
    FUN_1001b620(piVar2,*(int **)(*piVar2 + 4));
    FUN_1002e346((void *)*piVar2);
    FUN_1002e346(*(void **)(param_1 + 8));
  }
  else {
    if (cVar1 == '\x02') {
      FUN_10018360(*(int **)(param_1 + 8));
      FUN_1002e346(*(void **)(param_1 + 8));
      return;
    }
    if (cVar1 == '\x03') {
      piVar2 = *(int **)(param_1 + 8);
      if (0xf < (uint)piVar2[5]) {
        pvVar3 = (void *)*piVar2;
        pvVar5 = pvVar3;
        if ((0xfff < piVar2[5] + 1U) &&
           (pvVar5 = *(void **)((int)pvVar3 + -4), 0x1f < (uint)((int)pvVar3 + (-4 - (int)pvVar5))))
        {
          FUN_10032f7f();
          pcVar4 = (code *)swi(3);
          (*pcVar4)();
          return;
        }
        FUN_1002e346(pvVar5);
      }
      piVar2[4] = 0;
      piVar2[5] = 0xf;
      *(undefined1 *)piVar2 = 0;
      FUN_1002e346(*(void **)(param_1 + 8));
      return;
    }
  }
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_1000e820 @ 1000e820