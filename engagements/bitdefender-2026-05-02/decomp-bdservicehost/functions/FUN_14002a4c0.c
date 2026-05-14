longlong *
FUN_14002a4c0(undefined8 *param_1,undefined8 *param_2,longlong param_3,undefined1 param_4)

{
  longlong *plVar1;
  longlong *plVar2;
  longlong *plVar3;
  
  plVar3 = (longlong *)*param_1;
  if (*(char *)((longlong)param_2 + 0x19) == '\0') {
    plVar1 = (longlong *)operator_new(0x50);
    FUN_14000e990(plVar1 + 4,param_2 + 4);
    FUN_140025c20((undefined1 *)(plVar1 + 8),(undefined1 *)(param_2 + 8));
    *plVar1 = (longlong)plVar3;
    plVar1[2] = (longlong)plVar3;
    *(undefined2 *)(plVar1 + 3) = 0;
    plVar1[1] = param_3;
    *(undefined1 *)(plVar1 + 3) = *(undefined1 *)(param_2 + 3);
    if (*(char *)((longlong)plVar3 + 0x19) != '\0') {
      plVar3 = plVar1;
    }
    plVar2 = FUN_14002a4c0(param_1,(undefined8 *)*param_2,(longlong)plVar1,param_4);
    *plVar1 = (longlong)plVar2;
    plVar2 = FUN_14002a4c0(param_1,(undefined8 *)param_2[2],(longlong)plVar1,param_4);
    plVar1[2] = (longlong)plVar2;
  }
  return plVar3;
}


// FUNCTION_END

// FUNCTION_START: FUN_14002a5c0 @ 14002a5c0