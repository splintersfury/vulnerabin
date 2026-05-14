void FUN_10009af0(undefined4 param_1,int *param_2)

{
  char cVar1;
  int *piVar2;
  void *pvVar3;
  code *pcVar4;
  void *pvVar5;
  
  cVar1 = *(char *)((int)param_2 + 0xd);
  do {
    if (cVar1 != '\0') {
      return;
    }
    FUN_10009af0(param_1,(int *)param_2[2]);
    piVar2 = (int *)*param_2;
    if ((undefined4 *)param_2[10] != (undefined4 *)0x0) {
      (*(code *)**(undefined4 **)param_2[10])(1);
    }
    if (7 < (uint)param_2[9]) {
      pvVar3 = (void *)param_2[4];
      pvVar5 = pvVar3;
      if ((0xfff < param_2[9] * 2 + 2U) &&
         (pvVar5 = *(void **)((int)pvVar3 + -4), 0x1f < (uint)((int)pvVar3 + (-4 - (int)pvVar5)))) {
        FUN_10032f7f();
        pcVar4 = (code *)swi(3);
        (*pcVar4)();
        return;
      }
      FUN_1002e346(pvVar5);
    }
    param_2[8] = 0;
    param_2[9] = 7;
    *(undefined2 *)(param_2 + 4) = 0;
    FUN_1002e346(param_2);
    cVar1 = *(char *)((int)piVar2 + 0xd);
    param_2 = piVar2;
  } while( true );
}


// FUNCTION_END

// FUNCTION_START: FUN_10009ba0 @ 10009ba0