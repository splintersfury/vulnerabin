void FUN_14002a3f0(undefined8 *param_1)

{
  char cVar1;
  longlong *plVar2;
  undefined8 uVar3;
  longlong *plVar4;
  longlong *plVar5;
  
  plVar2 = (longlong *)param_1[1];
  if (plVar2 != (longlong *)0x0) {
    uVar3 = *param_1;
    cVar1 = *(char *)((longlong)*(longlong **)(*plVar2 + 8) + 0x19);
    plVar5 = *(longlong **)(*plVar2 + 8);
    while (cVar1 == '\0') {
      FUN_140029be0(plVar2,uVar3,(longlong *)plVar5[2]);
      plVar4 = (longlong *)*plVar5;
      FUN_140029e10(plVar5 + 4);
      FUN_14002f180();
      plVar5 = plVar4;
      cVar1 = *(char *)((longlong)plVar4 + 0x19);
    }
    FUN_14002f180();
  }
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_14002a480 @ 14002a480