void __fastcall FUN_100127b0(undefined4 *param_1)

{
  uint *puVar1;
  undefined1 uVar2;
  undefined4 uVar3;
  undefined4 uStack_8;
  
  param_1[4] = param_1[4] + 1;
  param_1[5] = param_1[5] + 1;
  uStack_8 = param_1;
  if (*(char *)(param_1 + 3) == '\0') {
    uVar3 = (*(code *)**(undefined4 **)*param_1)();
    param_1[2] = uVar3;
  }
  else {
    *(undefined1 *)(param_1 + 3) = 0;
  }
  if (param_1[2] != -1) {
    puVar1 = (uint *)param_1[8];
    uVar2 = (undefined1)param_1[2];
    uStack_8 = (undefined4 *)CONCAT13(uVar2,(undefined3)uStack_8);
    if (puVar1 == (uint *)param_1[9]) {
      FUN_100174f0(param_1 + 7,puVar1,(undefined1 *)((int)&uStack_8 + 3));
    }
    else {
      *(undefined1 *)puVar1 = uVar2;
      param_1[8] = param_1[8] + 1;
    }
  }
  if (param_1[2] == 10) {
    param_1[6] = param_1[6] + 1;
    param_1[5] = 0;
  }
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_10012810 @ 10012810