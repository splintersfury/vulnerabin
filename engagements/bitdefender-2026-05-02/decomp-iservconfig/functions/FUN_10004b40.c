undefined2 __fastcall FUN_10004b40(int param_1)

{
  int *piVar1;
  undefined2 *puVar2;
  undefined2 *puVar3;
  int iVar4;
  undefined2 *puVar5;
  
  piVar1 = *(int **)(param_1 + 0x1c);
  puVar2 = (undefined2 *)*piVar1;
  if (puVar2 != (undefined2 *)0x0) {
    if (puVar2 < puVar2 + **(int **)(param_1 + 0x2c)) {
      return *puVar2;
    }
    puVar3 = (undefined2 *)**(undefined4 **)(param_1 + 0x20);
    if ((puVar3 != (undefined2 *)0x0) && ((*(byte *)(param_1 + 0x3c) & 4) == 0)) {
      puVar5 = *(undefined2 **)(param_1 + 0x38);
      if (*(undefined2 **)(param_1 + 0x38) < puVar3) {
        puVar5 = puVar3;
      }
      if (puVar2 < puVar5) {
        *(undefined2 **)(param_1 + 0x38) = puVar5;
        iVar4 = *piVar1;
        *piVar1 = iVar4;
        **(int **)(param_1 + 0x2c) = (int)puVar5 - iVar4 >> 1;
        return *(undefined2 *)**(undefined4 **)(param_1 + 0x1c);
      }
    }
  }
  return 0xffff;
}


// FUNCTION_END

// FUNCTION_START: FUN_10004ba0 @ 10004ba0