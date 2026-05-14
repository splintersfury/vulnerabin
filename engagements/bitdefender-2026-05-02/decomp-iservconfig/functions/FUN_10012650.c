uint __fastcall FUN_10012650(undefined4 *param_1)

{
  uint *puVar1;
  undefined1 uVar2;
  undefined4 uVar3;
  uint uVar4;
  int iVar5;
  int iVar6;
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
  iVar5 = param_1[2];
  if (iVar5 == 10) {
    param_1[6] = param_1[6] + 1;
    param_1[5] = 0;
    iVar6 = param_1[5];
  }
  else {
    iVar6 = param_1[5];
    if (iVar5 == 0xef) {
      param_1[4] = param_1[4] + 1;
      param_1[5] = iVar6 + 1;
      if (*(char *)(param_1 + 3) == '\0') {
        iVar5 = (*(code *)**(undefined4 **)*param_1)();
        param_1[2] = iVar5;
        if (iVar5 != -1) goto LAB_10012706;
      }
      else {
        *(undefined1 *)(param_1 + 3) = 0;
        iVar5 = 0xef;
LAB_10012706:
        puVar1 = (uint *)param_1[8];
        uStack_8 = (undefined4 *)CONCAT13((char)iVar5,(undefined3)uStack_8);
        if (puVar1 == (uint *)param_1[9]) {
          FUN_100174f0(param_1 + 7,puVar1,(undefined1 *)((int)&uStack_8 + 3));
        }
        else {
          *(char *)puVar1 = (char)iVar5;
          param_1[8] = param_1[8] + 1;
        }
      }
      uVar4 = param_1[2];
      if (uVar4 == 10) goto LAB_1001272d;
      if (uVar4 != 0xbb) goto LAB_10012793;
      param_1[4] = param_1[4] + 1;
      param_1[5] = param_1[5] + 1;
      if (*(char *)(param_1 + 3) == '\0') {
        iVar5 = (*(code *)**(undefined4 **)*param_1)();
        param_1[2] = iVar5;
        if (iVar5 != -1) goto LAB_10012765;
      }
      else {
        *(undefined1 *)(param_1 + 3) = 0;
        iVar5 = 0xbb;
LAB_10012765:
        puVar1 = (uint *)param_1[8];
        uStack_8 = (undefined4 *)CONCAT13((char)iVar5,(undefined3)uStack_8);
        if (puVar1 == (uint *)param_1[9]) {
          FUN_100174f0(param_1 + 7,puVar1,(undefined1 *)((int)&uStack_8 + 3));
        }
        else {
          *(char *)puVar1 = (char)iVar5;
          param_1[8] = param_1[8] + 1;
        }
      }
      uVar4 = param_1[2];
      if (uVar4 == 10) {
LAB_1001272d:
        param_1[6] = param_1[6] + 1;
        param_1[5] = 0;
        return uVar4 & 0xffffff00;
      }
      if (uVar4 != 0xbf) {
LAB_10012793:
        return uVar4 & 0xffffff00;
      }
      goto LAB_100127a8;
    }
  }
  *(undefined1 *)(param_1 + 3) = 1;
  param_1[4] = param_1[4] + -1;
  if (iVar6 == 0) {
    uVar4 = param_1[6];
    if (uVar4 != 0) {
      uVar4 = uVar4 - 1;
      param_1[6] = uVar4;
    }
  }
  else {
    uVar4 = iVar6 - 1;
    param_1[5] = uVar4;
  }
  if (iVar5 != -1) {
    param_1[8] = param_1[8] + -1;
  }
LAB_100127a8:
  return CONCAT31((int3)(uVar4 >> 8),1);
}


// FUNCTION_END

// FUNCTION_START: FUN_100127b0 @ 100127b0