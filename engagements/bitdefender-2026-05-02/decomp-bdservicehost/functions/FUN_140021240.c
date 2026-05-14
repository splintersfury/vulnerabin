undefined8 FUN_140021240(undefined8 *param_1,undefined8 *param_2,undefined8 param_3)

{
  int iVar1;
  ulonglong uVar2;
  ulonglong uVar3;
  int *piVar4;
  undefined4 uVar5;
  undefined8 *puVar6;
  int *piVar7;
  undefined1 local_28 [16];
  
  uVar2 = param_1[0xb];
  uVar3 = param_1[0xc];
  if (uVar2 < uVar3) {
    param_1[0xb] = uVar2 + 1;
    puVar6 = param_1 + 9;
    if (0xf < uVar3) {
      puVar6 = (undefined8 *)param_1[9];
    }
    *(undefined1 *)((longlong)puVar6 + uVar2) = *(undefined1 *)(param_1 + 2);
    *(undefined1 *)((longlong)puVar6 + uVar2 + 1) = 0;
  }
  else {
    puVar6 = FUN_1400137e0(param_1 + 9,uVar3,param_3,*(undefined1 *)(param_1 + 2));
  }
  piVar7 = (int *)*param_2;
  piVar4 = (int *)param_2[1];
  while( true ) {
    if (piVar7 == piVar4) {
      return CONCAT71((int7)((ulonglong)puVar6 >> 8),1);
    }
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
      local_28[0] = (undefined1)*(int *)(param_1 + 2);
      if (puVar6 == (undefined8 *)param_1[8]) {
        FUN_140024dc0(param_1 + 6,puVar6,local_28);
      }
      else {
        *(undefined1 *)puVar6 = local_28[0];
        param_1[7] = param_1[7] + 1;
      }
    }
    iVar1 = *(int *)(param_1 + 2);
    if (iVar1 == 10) {
      param_1[5] = param_1[5] + 1;
      param_1[4] = 0;
    }
    if ((iVar1 < *piVar7) || (piVar7[1] < iVar1)) break;
    uVar2 = param_1[0xb];
    uVar3 = param_1[0xc];
    if (uVar2 < uVar3) {
      param_1[0xb] = uVar2 + 1;
      puVar6 = param_1 + 9;
      if (0xf < uVar3) {
        puVar6 = (undefined8 *)param_1[9];
      }
      *(char *)((longlong)puVar6 + uVar2) = (char)iVar1;
      *(undefined1 *)((longlong)puVar6 + uVar2 + 1) = 0;
    }
    else {
      puVar6 = FUN_1400137e0(param_1 + 9,uVar2,uVar3,(char)iVar1);
    }
    piVar7 = piVar7 + 2;
  }
  param_1[0xd] = "invalid string: ill-formed UTF-8 byte";
  return "st be escaped to \\u001F";
}


// FUNCTION_END

// FUNCTION_START: FUN_140021390 @ 140021390