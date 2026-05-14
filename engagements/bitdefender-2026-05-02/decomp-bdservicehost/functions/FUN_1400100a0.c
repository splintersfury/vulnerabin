longlong * FUN_1400100a0(longlong param_1,longlong *param_2)

{
  undefined8 *puVar1;
  ulonglong uVar2;
  
  *param_2 = 0;
  param_2[2] = 0;
  param_2[3] = 7;
  *(undefined2 *)param_2 = 0;
  if ((((byte)*(uint *)(param_1 + 0x70) & 0x22) == 2) ||
     (uVar2 = **(ulonglong **)(param_1 + 0x40), uVar2 == 0)) {
    if (((*(uint *)(param_1 + 0x70) & 4) == 0) && (**(longlong **)(param_1 + 0x38) != 0)) {
      puVar1 = (undefined8 *)**(longlong **)(param_1 + 0x18);
      uVar2 = ((longlong)**(int **)(param_1 + 0x50) * 2 - (longlong)puVar1) +
              **(longlong **)(param_1 + 0x38) >> 1;
    }
    else {
      uVar2 = 0;
      puVar1 = (undefined8 *)0x0;
    }
  }
  else {
    puVar1 = (undefined8 *)**(longlong **)(param_1 + 0x20);
    if (uVar2 < *(ulonglong *)(param_1 + 0x68)) {
      uVar2 = *(ulonglong *)(param_1 + 0x68);
    }
    uVar2 = (longlong)(uVar2 - (longlong)puVar1) >> 1;
  }
  if (puVar1 != (undefined8 *)0x0) {
    FUN_140010340(param_2,puVar1,uVar2);
  }
  return param_2;
}


// FUNCTION_END

// FUNCTION_START: FUN_140010160 @ 140010160