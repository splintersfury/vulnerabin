undefined1 * FUN_1400089c0(undefined1 *param_1,undefined1 *param_2,undefined8 param_3)

{
  longlong *plVar1;
  longlong *plVar2;
  undefined4 uVar3;
  undefined8 uVar4;
  longlong local_58 [7];
  longlong *local_20;
  
  *param_1 = 0;
  *(undefined8 *)(param_1 + 8) = 0;
  *(undefined8 *)(param_1 + 0x10) = 0;
  *(undefined8 *)(param_1 + 0x18) = 0;
  *(undefined8 *)(param_1 + 0x20) = 0;
  param_1[0x68] = 0;
  *(undefined4 *)(param_1 + 0x70) = 0;
  uVar3 = FUN_1400083c0((longlong)param_2,param_2,param_3);
  *(undefined4 *)(param_1 + 0x70) = uVar3;
  *param_1 = *param_2;
  *(undefined8 *)(param_1 + 8) = *(undefined8 *)(param_2 + 8);
  *(undefined8 *)(param_1 + 0x10) = *(undefined8 *)(param_2 + 0x10);
  *(undefined8 *)(param_1 + 0x18) = *(undefined8 *)(param_2 + 0x18);
  *(undefined8 *)(param_1 + 0x20) = *(undefined8 *)(param_2 + 0x20);
  plVar1 = (longlong *)(param_1 + 0x28);
  if (param_2[0x68] == '\0') {
    if (param_1[0x68] != '\0') {
      plVar2 = *(longlong **)(param_1 + 0x60);
      if (plVar2 != (longlong *)0x0) {
        (*(code *)PTR__guard_dispatch_icall_14005b538)(plVar2,plVar2 != plVar1);
        *(undefined8 *)(param_1 + 0x60) = 0;
      }
      param_1[0x68] = 0;
    }
  }
  else if (param_1[0x68] == '\0') {
    *(undefined8 *)(param_1 + 0x60) = 0;
    if (*(longlong *)(param_2 + 0x60) != 0) {
      uVar4 = (*(code *)PTR__guard_dispatch_icall_14005b538)(*(longlong *)(param_2 + 0x60),plVar1);
      *(undefined8 *)(param_1 + 0x60) = uVar4;
    }
    param_1[0x68] = 1;
  }
  else {
    local_20 = (longlong *)0x0;
    if (*(longlong *)(param_2 + 0x60) != 0) {
      local_20 = (longlong *)
                 (*(code *)PTR__guard_dispatch_icall_14005b538)
                           (*(longlong *)(param_2 + 0x60),local_58);
    }
    FUN_140014df0(local_58,plVar1);
    if (local_20 != (longlong *)0x0) {
      (*(code *)PTR__guard_dispatch_icall_14005b538)
                (local_20,CONCAT71((int7)((ulonglong)local_58 >> 8),local_20 != local_58));
    }
  }
  return param_1;
}


// FUNCTION_END

// FUNCTION_START: FUN_140008b00 @ 140008b00