void FUN_10018760(void *param_1,int param_2)

{
  code *pcVar1;
  void *pvVar2;
  
  pvVar2 = param_1;
  if ((0xfff < (uint)(param_2 * 0x10)) &&
     (pvVar2 = *(void **)((int)param_1 + -4), 0x1f < (uint)((int)param_1 + (-4 - (int)pvVar2)))) {
    FUN_10032f7f();
    pcVar1 = (code *)swi(3);
    (*pcVar1)();
    return;
  }
  FUN_1002e346(pvVar2);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_100187a0 @ 100187a0