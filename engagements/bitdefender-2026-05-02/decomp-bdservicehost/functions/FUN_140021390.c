void FUN_140021390(undefined8 *param_1)

{
  int iVar1;
  undefined8 *puVar2;
  undefined4 uVar3;
  ulonglong *puVar4;
  undefined1 auStack_48 [32];
  undefined1 local_28 [8];
  undefined4 local_20;
  undefined4 local_1c;
  undefined8 local_18;
  ulonglong local_10;
  
  local_10 = DAT_14007a060 ^ (ulonglong)auStack_48;
  local_20 = 0xc;
  local_1c = 8;
  local_18 = 4;
  puVar4 = (ulonglong *)&local_20;
  while( true ) {
    param_1[3] = param_1[3] + 1;
    param_1[4] = param_1[4] + 1;
    if (*(char *)((longlong)param_1 + 0x14) == '\0') {
      uVar3 = (*(code *)PTR__guard_dispatch_icall_14005b538)();
      *(undefined4 *)(param_1 + 2) = uVar3;
    }
    else {
      *(undefined1 *)((longlong)param_1 + 0x14) = 0;
    }
    if (*(int *)(param_1 + 2) != -1) {
      puVar2 = (undefined8 *)param_1[7];
      local_28[0] = (undefined1)*(int *)(param_1 + 2);
      if (puVar2 == (undefined8 *)param_1[8]) {
        FUN_140024dc0(param_1 + 6,puVar2,local_28);
      }
      else {
        *(undefined1 *)puVar2 = local_28[0];
        param_1[7] = param_1[7] + 1;
      }
    }
    iVar1 = *(int *)(param_1 + 2);
    if (iVar1 == 10) break;
    if ((((9 < iVar1 - 0x30U) && (5 < iVar1 - 0x41U)) && (5 < iVar1 - 0x61U)) ||
       (puVar4 = (ulonglong *)((longlong)puVar4 + 4), puVar4 == &local_10)) goto LAB_14002148e;
  }
  param_1[5] = param_1[5] + 1;
  param_1[4] = 0;
LAB_14002148e:
  FUN_14002f160(local_10 ^ (ulonglong)auStack_48);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_1400214b0 @ 1400214b0