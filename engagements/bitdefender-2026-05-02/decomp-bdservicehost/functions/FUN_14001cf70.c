void FUN_14001cf70(char *param_1)

{
  char cVar1;
  longlong *plVar2;
  code *pcVar3;
  
  cVar1 = *param_1;
  if (cVar1 == '\x01') {
    FUN_140025800(*(longlong **)(param_1 + 8));
    FUN_14002f180();
    return;
  }
  if (cVar1 == '\x02') {
    FUN_140025b90(*(longlong **)(param_1 + 8));
    FUN_14002f180();
    return;
  }
  if (cVar1 == '\x03') {
    plVar2 = *(longlong **)(param_1 + 8);
    if (0xf < (ulonglong)plVar2[3]) {
      if ((0xfff < plVar2[3] + 1U) && (0x1f < (*plVar2 - *(longlong *)(*plVar2 + -8)) - 8U)) {
        FUN_140035d28();
        pcVar3 = (code *)swi(3);
        (*pcVar3)();
        return;
      }
      FUN_14002f180();
    }
    plVar2[2] = 0;
    plVar2[3] = 0xf;
    *(undefined1 *)plVar2 = 0;
    FUN_14002f180();
  }
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_14001d040 @ 14001d040