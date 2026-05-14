ulonglong FUN_14001f960(undefined8 *param_1)

{
  int iVar1;
  uint uVar2;
  undefined8 *puVar3;
  undefined1 uVar4;
  undefined4 uVar5;
  undefined8 *puVar6;
  longlong lVar7;
  undefined1 local_res8 [32];
  
  param_1[3] = param_1[3] + 1;
  param_1[4] = param_1[4] + 1;
  if (*(char *)((longlong)param_1 + 0x14) == '\0') {
    uVar5 = (*(code *)PTR__guard_dispatch_icall_14005b538)();
    *(undefined4 *)(param_1 + 2) = uVar5;
  }
  else {
    *(undefined1 *)((longlong)param_1 + 0x14) = 0;
  }
  if (*(int *)(param_1 + 2) != -1) {
    puVar6 = (undefined8 *)param_1[7];
    local_res8[0] = (undefined1)*(int *)(param_1 + 2);
    if (puVar6 == (undefined8 *)param_1[8]) {
      FUN_140024dc0(param_1 + 6,puVar6,local_res8);
    }
    else {
      *(undefined1 *)puVar6 = local_res8[0];
      param_1[7] = param_1[7] + 1;
    }
  }
  iVar1 = *(int *)(param_1 + 2);
  if (iVar1 == 10) {
    param_1[5] = param_1[5] + 1;
    param_1[4] = 0;
    lVar7 = param_1[4];
  }
  else {
    lVar7 = param_1[4];
    if (iVar1 == 0xef) {
      param_1[3] = param_1[3] + 1;
      param_1[4] = lVar7 + 1;
      if (*(char *)((longlong)param_1 + 0x14) == '\0') {
        puVar6 = (undefined8 *)(*(code *)PTR__guard_dispatch_icall_14005b538)();
        *(int *)(param_1 + 2) = (int)puVar6;
        uVar4 = (char)puVar6;
        if ((int)puVar6 != -1) goto LAB_14001fa48;
      }
      else {
        *(undefined1 *)((longlong)param_1 + 0x14) = 0;
        uVar4 = 0xef;
LAB_14001fa48:
        local_res8[0] = uVar4;
        puVar6 = (undefined8 *)param_1[7];
        if (puVar6 == (undefined8 *)param_1[8]) {
          puVar6 = (undefined8 *)FUN_140024dc0(param_1 + 6,puVar6,local_res8);
        }
        else {
          *(undefined1 *)puVar6 = local_res8[0];
          param_1[7] = param_1[7] + 1;
        }
      }
      if (*(int *)(param_1 + 2) == 10) goto LAB_14001fa77;
      puVar6 = (undefined8 *)0xbb;
      if (*(int *)(param_1 + 2) != 0xbb) goto LAB_14001faf2;
      param_1[3] = param_1[3] + 1;
      param_1[4] = param_1[4] + 1;
      if (*(char *)((longlong)param_1 + 0x14) == '\0') {
        puVar6 = (undefined8 *)(*(code *)PTR__guard_dispatch_icall_14005b538)();
        *(int *)(param_1 + 2) = (int)puVar6;
        if ((int)puVar6 != -1) goto LAB_14001fabf;
      }
      else {
        *(undefined1 *)((longlong)param_1 + 0x14) = 0;
LAB_14001fabf:
        puVar3 = (undefined8 *)param_1[7];
        local_res8[0] = SUB81(puVar6,0);
        if (puVar3 == (undefined8 *)param_1[8]) {
          FUN_140024dc0(param_1 + 6,puVar3,local_res8);
        }
        else {
          *(undefined1 *)puVar3 = local_res8[0];
          param_1[7] = param_1[7] + 1;
        }
      }
      uVar2 = *(uint *)(param_1 + 2);
      puVar6 = (undefined8 *)(ulonglong)uVar2;
      if (uVar2 == 10) {
LAB_14001fa77:
        param_1[5] = param_1[5] + 1;
        param_1[4] = 0;
        return (ulonglong)puVar6 & 0xffffffffffffff00;
      }
      if (uVar2 != 0xbf) {
LAB_14001faf2:
        return (ulonglong)puVar6 & 0xffffffffffffff00;
      }
      goto LAB_14001fb0c;
    }
  }
  *(undefined1 *)((longlong)param_1 + 0x14) = 1;
  param_1[3] = param_1[3] + -1;
  if (lVar7 == 0) {
    puVar6 = (undefined8 *)param_1[5];
    if (puVar6 != (undefined8 *)0x0) {
      puVar6 = (undefined8 *)((longlong)puVar6 + -1);
      param_1[5] = puVar6;
    }
  }
  else {
    puVar6 = (undefined8 *)(lVar7 + -1);
    param_1[4] = puVar6;
  }
  if (iVar1 != -1) {
    param_1[7] = param_1[7] + -1;
  }
LAB_14001fb0c:
  return CONCAT71((int7)((ulonglong)puVar6 >> 8),1);
}


// FUNCTION_END

// FUNCTION_START: FUN_14001fb20 @ 14001fb20