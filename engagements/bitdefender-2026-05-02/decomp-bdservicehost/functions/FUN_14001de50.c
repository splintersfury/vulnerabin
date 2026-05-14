void FUN_14001de50(char *param_1,char param_2)

{
  void *pvVar1;
  undefined8 *puVar2;
  longlong *plVar3;
  char *pcVar4;
  undefined1 auStack_98 [32];
  undefined8 local_78 [7];
  undefined1 local_40 [8];
  undefined1 *local_38;
  longlong *plStack_30;
  ulonglong local_18;
  
  local_18 = DAT_14007a060 ^ (ulonglong)auStack_98;
  *param_1 = param_2;
  switch(param_2) {
  case '\0':
  case '\x05':
  case '\x06':
  case '\a':
    param_1[8] = '\0';
    param_1[9] = '\0';
    param_1[10] = '\0';
    param_1[0xb] = '\0';
    param_1[0xc] = '\0';
    param_1[0xd] = '\0';
    param_1[0xe] = '\0';
    param_1[0xf] = '\0';
    break;
  case '\x01':
    local_38 = (undefined1 *)0x0;
    plStack_30 = (longlong *)0x0;
    plVar3 = (longlong *)operator_new(0x10);
    local_38 = local_40;
    *plVar3 = 0;
    plVar3[1] = 0;
    plStack_30 = plVar3;
    pvVar1 = operator_new(0x50);
    *(void **)pvVar1 = pvVar1;
    *(void **)((longlong)pvVar1 + 8) = pvVar1;
    *(void **)((longlong)pvVar1 + 0x10) = pvVar1;
    *(undefined2 *)((longlong)pvVar1 + 0x18) = 0x101;
    *plVar3 = (longlong)pvVar1;
    goto LAB_14001dedf;
  case '\x02':
    puVar2 = (undefined8 *)operator_new(0x18);
    *puVar2 = 0;
    puVar2[1] = 0;
    puVar2[2] = 0;
    *(undefined8 **)(param_1 + 8) = puVar2;
    break;
  case '\x03':
    local_38 = (undefined1 *)0x0;
    plStack_30 = (longlong *)0x0;
    plVar3 = (longlong *)operator_new(0x20);
    local_38 = local_40;
    *plVar3 = 0;
    plVar3[2] = 0;
    plVar3[3] = 0xf;
    plStack_30 = plVar3;
    FUN_1400106a0(plVar3,(undefined8 *)&DAT_14006a933,0);
LAB_14001dedf:
    *(longlong **)(param_1 + 8) = plVar3;
    break;
  case '\x04':
    param_1[8] = '\0';
    break;
  default:
    param_1[8] = '\0';
    param_1[9] = '\0';
    param_1[10] = '\0';
    param_1[0xb] = '\0';
    param_1[0xc] = '\0';
    param_1[0xd] = '\0';
    param_1[0xe] = '\0';
    param_1[0xf] = '\0';
    if (param_2 == '\0') {
      pcVar4 = "961c151d2e87f2686a955a9be24d316f1362bf21 3.7.0";
      FUN_14000e950((longlong *)&local_38,
                    (undefined8 *)"961c151d2e87f2686a955a9be24d316f1362bf21 3.7.0");
      FUN_1400194a0(local_78,pcVar4,&local_38);
                    /* WARNING: Subroutine does not return */
      _CxxThrowException(local_78,(ThrowInfo *)&DAT_140077ba8);
    }
  }
  FUN_14002f160(local_18 ^ (ulonglong)auStack_98);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_14001dff0 @ 14001dff0