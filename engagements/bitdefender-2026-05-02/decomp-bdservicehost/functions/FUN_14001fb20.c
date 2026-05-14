undefined4 FUN_14001fb20(undefined8 *param_1,longlong param_2,ulonglong param_3,undefined4 param_4)

{
  undefined8 *puVar1;
  undefined4 uVar2;
  ulonglong uVar3;
  undefined1 local_res18 [8];
  
  uVar3 = 1;
  if (1 < param_3) {
    do {
      param_1[3] = param_1[3] + 1;
      param_1[4] = param_1[4] + 1;
      if (*(char *)((longlong)param_1 + 0x14) == '\0') {
        uVar2 = (*(code *)PTR__guard_dispatch_icall_14005b538)();
        *(undefined4 *)(param_1 + 2) = uVar2;
      }
      else {
        *(undefined1 *)((longlong)param_1 + 0x14) = 0;
      }
      if (*(int *)(param_1 + 2) != -1) {
        puVar1 = (undefined8 *)param_1[7];
        local_res18[0] = (undefined1)*(int *)(param_1 + 2);
        if (puVar1 == (undefined8 *)param_1[8]) {
          FUN_140024dc0(param_1 + 6,puVar1,local_res18);
        }
        else {
          *(undefined1 *)puVar1 = local_res18[0];
          param_1[7] = param_1[7] + 1;
        }
      }
      if (*(int *)(param_1 + 2) == 10) {
        param_1[5] = param_1[5] + 1;
        param_1[4] = 0;
      }
      if (*(int *)(param_1 + 2) != (int)*(char *)(uVar3 + param_2)) {
        param_1[0xd] = "invalid literal";
        return param_4;
      }
      uVar3 = uVar3 + 1;
    } while (uVar3 < param_3);
  }
  return param_4;
}


// FUNCTION_END

// FUNCTION_START: FUN_14001fc00 @ 14001fc00