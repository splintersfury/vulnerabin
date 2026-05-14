void FUN_140026960(undefined8 *param_1,undefined8 *param_2)

{
  char *pcVar1;
  longlong *plVar2;
  undefined8 *puVar3;
  undefined8 *puVar4;
  undefined1 auStack_68 [32];
  char local_48 [8];
  undefined8 local_40;
  undefined1 local_38 [8];
  undefined1 *local_30;
  undefined8 *puStack_28;
  ulonglong local_20;
  
  local_20 = DAT_14007a060 ^ (ulonglong)auStack_68;
  if (param_1[1] == param_1[2]) {
    local_30 = (undefined1 *)0x0;
    puStack_28 = (undefined8 *)0x0;
    puVar3 = (undefined8 *)operator_new(0x20);
    local_30 = local_38;
    puStack_28 = puVar3;
    FUN_14000e990(puVar3,param_2);
    pcVar1 = (char *)*param_1;
    local_48[0] = *pcVar1;
    *pcVar1 = '\x03';
    local_40 = *(undefined8 *)(pcVar1 + 8);
    *(undefined8 **)(pcVar1 + 8) = puVar3;
    FUN_14001cf70(local_48);
  }
  else {
    pcVar1 = *(char **)(param_1[2] + -8);
    if (*pcVar1 == '\x02') {
      plVar2 = *(longlong **)(pcVar1 + 8);
      puVar3 = (undefined8 *)plVar2[1];
      if (puVar3 == (undefined8 *)plVar2[2]) {
        FUN_140029070(plVar2,puVar3,param_2);
      }
      else {
        puVar3[1] = 0;
        *(undefined1 *)puVar3 = 3;
        local_30 = (undefined1 *)0x0;
        puStack_28 = (undefined8 *)0x0;
        puVar4 = (undefined8 *)operator_new(0x20);
        local_30 = local_38;
        puStack_28 = puVar4;
        FUN_14000e990(puVar4,param_2);
        puVar3[1] = puVar4;
        plVar2[1] = plVar2[1] + 0x10;
      }
    }
    else {
      local_30 = (undefined1 *)0x0;
      puStack_28 = (undefined8 *)0x0;
      puVar3 = (undefined8 *)operator_new(0x20);
      local_30 = local_38;
      puStack_28 = puVar3;
      FUN_14000e990(puVar3,param_2);
      pcVar1 = (char *)param_1[4];
      local_48[0] = *pcVar1;
      *pcVar1 = '\x03';
      local_40 = *(undefined8 *)(pcVar1 + 8);
      *(undefined8 **)(pcVar1 + 8) = puVar3;
      FUN_14001cf70(local_48);
    }
  }
  FUN_14002f160(local_20 ^ (ulonglong)auStack_68);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_140026af0 @ 140026af0