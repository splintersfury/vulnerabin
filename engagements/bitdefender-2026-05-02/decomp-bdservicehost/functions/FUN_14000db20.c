undefined2 FUN_14000db20(longlong param_1)

{
  longlong *plVar1;
  undefined2 *puVar2;
  undefined2 *puVar3;
  longlong lVar4;
  undefined2 *puVar5;
  
  plVar1 = *(longlong **)(param_1 + 0x38);
  puVar2 = (undefined2 *)*plVar1;
  if (puVar2 != (undefined2 *)0x0) {
    if (puVar2 < puVar2 + **(int **)(param_1 + 0x50)) {
      return *puVar2;
    }
    puVar3 = (undefined2 *)**(undefined8 **)(param_1 + 0x40);
    if ((puVar3 != (undefined2 *)0x0) && ((*(byte *)(param_1 + 0x70) & 4) == 0)) {
      puVar5 = *(undefined2 **)(param_1 + 0x68);
      if (*(undefined2 **)(param_1 + 0x68) < puVar3) {
        puVar5 = puVar3;
      }
      if (puVar2 < puVar5) {
        *(undefined2 **)(param_1 + 0x68) = puVar5;
        lVar4 = *plVar1;
        *plVar1 = lVar4;
        **(undefined4 **)(param_1 + 0x50) = (int)((longlong)puVar5 - lVar4 >> 1);
        return *(undefined2 *)**(undefined8 **)(param_1 + 0x38);
      }
    }
  }
  return 0xffff;
}


// FUNCTION_END

// FUNCTION_START: FUN_14000db90 @ 14000db90