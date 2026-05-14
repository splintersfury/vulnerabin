void __fastcall FUN_10011510(int param_1)

{
  int *piVar1;
  void *pvVar2;
  code *pcVar3;
  void *pvVar4;
  
  FUN_1000e760((char *)(param_1 + 0x68));
  piVar1 = *(int **)(param_1 + 0x5c);
  if (piVar1 != (int *)0x0) {
    (**(code **)(*piVar1 + 0x10))(piVar1 != (int *)(param_1 + 0x38));
    *(undefined4 *)(param_1 + 0x5c) = 0;
  }
  pvVar2 = *(void **)(param_1 + 0x20);
  if (pvVar2 != (void *)0x0) {
    pvVar4 = pvVar2;
    if ((0xfff < (*(int *)(param_1 + 0x28) - (int)pvVar2 & 0xfffffffcU)) &&
       (pvVar4 = *(void **)((int)pvVar2 + -4), 0x1f < (uint)((int)pvVar2 + (-4 - (int)pvVar4))))
    goto LAB_1001161a;
    FUN_1002e346(pvVar4);
    *(undefined4 *)(param_1 + 0x20) = 0;
    *(undefined4 *)(param_1 + 0x24) = 0;
    *(undefined4 *)(param_1 + 0x28) = 0;
  }
  pvVar2 = *(void **)(param_1 + 0x10);
  if (pvVar2 != (void *)0x0) {
    pvVar4 = pvVar2;
    if ((0xfff < (*(int *)(param_1 + 0x18) - (int)pvVar2 & 0xfffffffcU)) &&
       (pvVar4 = *(void **)((int)pvVar2 + -4), 0x1f < (uint)((int)pvVar2 + (-4 - (int)pvVar4))))
    goto LAB_1001161a;
    FUN_1002e346(pvVar4);
    *(undefined4 *)(param_1 + 0x10) = 0;
    *(undefined4 *)(param_1 + 0x14) = 0;
    *(undefined4 *)(param_1 + 0x18) = 0;
  }
  pvVar2 = *(void **)(param_1 + 4);
  if (pvVar2 != (void *)0x0) {
    pvVar4 = pvVar2;
    if ((0xfff < (*(int *)(param_1 + 0xc) - (int)pvVar2 & 0xfffffffcU)) &&
       (pvVar4 = *(void **)((int)pvVar2 + -4), 0x1f < (uint)((int)pvVar2 + (-4 - (int)pvVar4)))) {
LAB_1001161a:
      FUN_10032f7f();
      pcVar3 = (code *)swi(3);
      (*pcVar3)();
      return;
    }
    FUN_1002e346(pvVar4);
    *(undefined4 *)(param_1 + 4) = 0;
    *(undefined4 *)(param_1 + 8) = 0;
    *(undefined4 *)(param_1 + 0xc) = 0;
  }
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_10011620 @ 10011620